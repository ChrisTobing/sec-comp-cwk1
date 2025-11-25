package comp3911.cwk2;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ConcurrentHashMap;

import io.github.cdimascio.dotenv.Dotenv; // Added for .env file

@SuppressWarnings("serial")
public class AppServlet extends HttpServlet {

  private static final String CONNECTION_URL;
  private static final String AUTH_QUERY = "select * from user where username = ? and password= ?";        
  private static final String SEARCH_QUERY = "select * from patient where surname= ? collate nocase";
  
  // Attempt tracking constants
  private static final int MAX_ATTEMPTS = 5;
  private static final long LOCKOUT_DURATION_MS = 1 * 60 * 1000; // 15 minutes in milliseconds

  private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
  private Connection database;
  
  /*
  Flaw Fix: Brute force protection - Track login attempts by IP address: IP -> AttemptInfo
  Implementation Steps:
  1. Add a method to get the client IP address from the request.
  2. Add a ConcurrentHashMap to map IP addresses to AttemptInfo objects.
  3. Add methods to increase, reset, and check lockout status for an IP address.
  4. Added a new template for the locked out page.
  5. Implemented the logic to check if the IP is locked out and display the appropriate template.
   */ 
  private final ConcurrentHashMap<String, AttemptInfo> attemptTracker = new ConcurrentHashMap<>();
  
  // Inner class to track attempt information
  private static class AttemptInfo {
    int attempts;
    long lockoutUntil; // timestamp when lockout expires (0 if not locked out)
    
    AttemptInfo() {
      this.attempts = 0;
      this.lockoutUntil = 0;
    }
  }

  // Load envrionment variables from .env, then get the connection URL
  static {
    Dotenv dotenv = Dotenv.load(); 
    CONNECTION_URL = dotenv.get("DB_CONNECTION_URL");
  }

  @Override
  public void init() throws ServletException {
    configureTemplateEngine();
    connectToDatabase();
  }

  private void configureTemplateEngine() throws ServletException {
    try {
      fm.setDirectoryForTemplateLoading(new File("./templates"));
      fm.setDefaultEncoding("UTF-8");
      fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
      fm.setLogTemplateExceptions(false);
      fm.setWrapUncheckedExceptions(true);
    }
    catch (IOException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private void connectToDatabase() throws ServletException {
    try {
      database = DriverManager.getConnection(CONNECTION_URL);
    }
    catch (SQLException error) {
      throw new ServletException(error.getMessage());
    }
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
   throws ServletException, IOException {
    try {
      String clientIp = getClientIp(request);
      Map<String, Object> model = new HashMap<>();
      
      // IP is Locked out, show the locked out page
      if (isLockedOut(clientIp)) {
        AttemptInfo info = attemptTracker.get(clientIp);
        if (info != null) {
          Template template = fm.getTemplate("locked.html");
          long remainingMinutes = (info.lockoutUntil - System.currentTimeMillis()) / (60 * 1000) + 1;
          model.put("remainingMinutes", remainingMinutes);
          template.process(model, response.getWriter());
        } else {
          Template template = fm.getTemplate("login.html");
          template.process(model, response.getWriter());
        }
      } else {
        // IP is not Locked out, show the login page
        AttemptInfo info = attemptTracker.get(clientIp);
        if (info != null && info.attempts > 0 && info.attempts < MAX_ATTEMPTS) {
          model.put("remainingAttempts", MAX_ATTEMPTS - info.attempts);
        }
        Template template = fm.getTemplate("login.html");
        template.process(model, response.getWriter());
      }
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    }
    catch (TemplateException error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
   throws ServletException, IOException {
    String clientIp = getClientIp(request);
    
    // Check if IP is currently locked out
    if (isLockedOut(clientIp)) {
      try {
        AttemptInfo info = attemptTracker.get(clientIp);
        Map<String, Object> model = new HashMap<>();
        long remainingMinutes = (info.lockoutUntil - System.currentTimeMillis()) / (60 * 1000) + 1;
        model.put("remainingMinutes", remainingMinutes);
        Template template = fm.getTemplate("locked.html");
        template.process(model, response.getWriter());
        response.setContentType("text/html");
        response.setStatus(HttpServletResponse.SC_OK);
        return;
      }
      catch (TemplateException error) {
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        return;
      }
    }
    
    // Get form parameters
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    String surname = request.getParameter("surname");

    try {
      if (authenticated(username, password)) {
        // Successful login, reset attempts
        resetAttempts(clientIp);
        
        // Get search results and merge with template
        Map<String, Object> model = new HashMap<>();
        model.put("records", searchResults(surname));
        Template template = fm.getTemplate("details.html");
        template.process(model, response.getWriter());
      }
      else {
        // Failed login, increment attempts
        incrementAttempts(clientIp);
        AttemptInfo info = attemptTracker.get(clientIp);
        
        Map<String, Object> model = new HashMap<>();
        model.put("remainingAttempts", MAX_ATTEMPTS - info.attempts);
        
        // Check if user reached max attempts
        if (info.attempts >= MAX_ATTEMPTS) {
          lockout(clientIp);
          long remainingMinutes = LOCKOUT_DURATION_MS / (60 * 1000);
          model.put("remainingMinutes", remainingMinutes);
          //Show the locked out page
          Template template = fm.getTemplate("locked.html");
          template.process(model, response.getWriter());
        } else {
          Template template = fm.getTemplate("invalid.html");
          template.process(model, response.getWriter());
        }
      }
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    }
    catch (Exception error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  private boolean authenticated(String username, String password) throws SQLException {
    String hashedPassword = hashPassword(password);
    // String query = String.format(AUTH_QUERY, username, hashedPassword);    
    try (PreparedStatement stmt = database.prepareStatement(AUTH_QUERY)) {        // prepared statement instead
      stmt.setString(1,username)
      stmt.setString(2,hashedPassword)   // use new hashed password
      
      try (ResultSet results = stmt.executeQuery(query))
        return results.next
      }
    }
  }

  private List<Record> searchResults(String surname) throws SQLException {
    List<Record> records = new ArrayList<>();

    // String query = String.format(SEARCH_QUERY, surname);
    try (PreparedStatement stmt = database.prepareStatement(SEARCH_QUERY)) {
      // ResultSet results = stmt.executeQuery(query);

      stmt.setString(1,surname)   
      
      try(ResultSet results = stmt.executeQuery()) {
        while (results.next()) {
          Record rec = new Record();
          rec.setSurname(results.getString(2));
          rec.setForename(results.getString(3));
          rec.setAddress(results.getString(4));
          rec.setDateOfBirth(results.getString(5));
          rec.setDoctorId(results.getString(6));
          rec.setDiagnosis(results.getString(7));
          records.add(rec);
        }
      }
    }

    
    return records;
  }

  private String hashPassword(String password) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] hash = md.digest(password.getBytes());

      StringBuilder hexString = new StringBuilder();
      for (byte b : hash) {
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) hexString.append('0');
        hexString.append(hex);
      }
      return hexString.toString();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA-256 not available", e);
    }
  }

  // METHODS FOR BRUTE FORCE PROTECTION
  /**
   * Get client IP address from request
   */
  private String getClientIp(HttpServletRequest request) {
    String ip = request.getHeader("X-Forwarded-For");
    if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
      ip = request.getHeader("X-Real-IP");
    }
    if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
      ip = request.getRemoteAddr();
    }
    return ip;
  }

  /**
   * Check if the given IP is currently locked out
   */
  private boolean isLockedOut(String ip) {
    AttemptInfo info = attemptTracker.get(ip);
    if (info == null) {
      return false;
    }
    
    // Check if lockout has expired
    if (info.lockoutUntil > 0 && System.currentTimeMillis() < info.lockoutUntil) {
      return true;
    }
    
    // Lockout expired, clear it
    if (info.lockoutUntil > 0 && System.currentTimeMillis() >= info.lockoutUntil) {
      resetAttempts(ip);
    }
    
    return false;
  }

  /**
   * Increment failed login attempts for the given IP
   */
  private void incrementAttempts(String ip) {
    attemptTracker.compute(ip, (key, info) -> {
      if (info == null) {
        info = new AttemptInfo();
      }
      info.attempts++;
      return info;
    });
  }

  /**
   * Lock out the given IP address
   */
  private void lockout(String ip) {
    attemptTracker.compute(ip, (key, info) -> {
      if (info == null) {
        info = new AttemptInfo();
      }
      info.lockoutUntil = System.currentTimeMillis() + LOCKOUT_DURATION_MS;
      return info;
    });
  }

  /**
   * Reset attempts for the given IP (on successful login)
   */
  private void resetAttempts(String ip) {
    attemptTracker.remove(ip);
  }

}
