<nav class="subnav">
  <a href="admin.php">Dashboard</a>
  <a href="admin_users.php">User Management</a>
  <a href="admin_logs.php">Login Logs</a>
  <a href="admin_uploads.php">File Uploads</a>
  <span><?php echo getenv('FLAG_USER_ESCALATION'); ?></span>
  <a href="logout.php">Logout</a>
</nav>
