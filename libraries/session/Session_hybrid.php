<?php
class Session_hybrid extends CI_Driver {
	// CodeIgniter
	protected $CI;
	// Cookie Options
	protected $cookie_lifetime;
	protected $cookie_path;
	protected $cookie_domain;
	protected $cookie_secure;
	protected $cookie_httponly;
	// Session Options
	protected $sess_cookie_name;
	// Database Options
	protected $sess_table_name;
	// Info from db to compare against
	protected $db_user_agent;
	protected $db_ip_address;
	protected $db_last_activity;

	public function __construct($params=array()){
		$this->CI = get_instance();

		// Get options from config file
		$options = array(
			'sess_table_name', 'sess_cookie_name',
			'cookie_lifetime', 'cookie_path',
			'cookie_domain', 'cookie_secure',
			'cookie_httponly'
		);
		foreach ($options as $key){
			$this->$key = (isset($params[$key])) ? $params[$key] : $this->CI->config->item($key);
		}

		// Set up session options before starting the session
		session_set_cookie_params(
			$this->cookie_lifetime ?: 0,
			$this->cookie_path ?: '/', $this->cookie_domain ?: null,
			$this->cookie_secure ?: false, $this->cookie_httponly ?: false
		);
		session_set_save_handler(
			array($this, '_open'), array($this, '_close'),
			array($this, '_read'), array($this, '_write'),
			array($this, '_destroy'), array($this, '_clean')
		);
		if($this->sess_cookie_name){
			session_name($this->sess_cookie_name);
		}

		// Start a native session, but with custom handlers
		session_start();
	}

	// --------------------------------------------------------------------

	/**
	 * Fetch the current session data if it exists
	 *
	 * @access	public
	 * @return	bool
	 */
	public function sess_read()
	{
		$session = $_SESSION;

		// Is the session data we unserialized an array with the correct format?
		if (!is_array($session))
		{
			log_message('debug', 'A session was not found.');
			$this->sess_destroy(FALSE);
			return FALSE;
		}

		// Is the session current?
		if (($this->db_last_activity + $this->parent->sess_expiration) < $this->parent->now)
		{
			$this->sess_destroy(FALSE);
			return FALSE;
		}

		// Does the IP Match?
		if ($this->parent->sess_match_ip == TRUE AND $this->db_ip_address != $this->CI->input->ip_address())
		{
			$this->sess_destroy(FALSE);
			return FALSE;
		}

		// Does the User Agent Match?
		if ($this->parent->sess_match_useragent == TRUE AND trim($this->db_user_agent) != trim(substr($this->CI->input->user_agent(), 0, 120)))
		{
			$this->sess_destroy(FALSE);
			return FALSE;
		}

		// Session is valid!
		$this->parent->userdata = $session;
		unset($session);

		return TRUE;
	}

	// --------------------------------------------------------------------

	/**
	 * Write the session data
	 *
	 * @access	public
	 * @return	void
	 */
	public function sess_write()
	{
		if( ! $this->parent->check_write())
		{
			$_SESSION = array();
			foreach($this->parent->userdata as $key => $val)
			{
				$_SESSION[$key] = $val;
			}

			$this->parent->track_write();
		}
	}

	// --------------------------------------------------------------------

	/**
	 * Create a new session
	 *
	 * @access	public
	 * @return	void
	 */
	public function sess_create()
	{
		if(session_id() == '') {
			session_start();
		}

		$this->parent->userdata = $_SESSION;
	}

	// --------------------------------------------------------------------

	/**
	 * Update an existing session
	 *
	 * @access	public
	 * @return	void
	 */
	public function sess_update()
	{
		// We only update the session every five minutes by default
		if (($this->db_last_activity + $this->parent->sess_time_to_update) >= $this->parent->now)
		{
			return;
		}

		// Regenerate session id
		session_regenerate_id();
	}

	// --------------------------------------------------------------------

	/**
	 * Destroy the current session
	 *
	 * @access	public
	 * @return	void
	 */
	public function sess_destroy($destroy = TRUE)
	{
		session_unset();
		session_regenerate_id();

		if($destroy)
			session_destroy();
	}

	// --------------------------------------------------------------------

	/**
	 * Session handling functions
	 *
	 * They need to be public, that's just how session_set_save_handler works
	 */
	public function _open(){
		// Are we using a database?  If so, load it
		if( !$this->sess_table_name ) {
			die('Session class database table name not configured');
		}
		$this->CI->load->database();

		return TRUE;
	}

	public function _close(){
		// This function is intentionally left empty
	}

	public function _read($id){
		// Get session info from database
		$this->CI->db->select('user_data, user_agent, ip_address, last_activity');
		$this->CI->db->from($this->sess_table_name);
		$this->CI->db->where('session_id', $id);
		$this->CI->db->limit(1);

		$result = $this->CI->db->get();

		if($result->num_rows() == 0){
			return '';
		}

		$row = $result->row();

		$this->db_user_agent = $row->user_agent;
		$this->db_ip_address = $row->ip_address;
		$this->db_last_activity = $row->last_activity;

		return $row->user_data;
	}

	public function _write($id, $data){
		// Write session data into database
		$info = array(
			'session_id' => $id,
			'user_agent' => substr($this->CI->input->user_agent(), 0, 120),
			'ip_address' => $this->CI->input->ip_address(),
			'last_activity' => $this->parent ? $this->parent->now : time(),
			'user_data' => $data
		);

		// This is called *AFTER* CodeIgniter is done, which means
		// the DB was closed.  Let's re-open it!
		$reOpenedDB = FALSE;
		$theDB = $this->CI->db;
		if($this->CI->db->conn_id === FALSE){
			$theDB = $this->CI->load->database('', TRUE);
			$reOpenedDB = TRUE;
		}

		$sql = $theDB->insert_string($this->sess_table_name, $info);
		$sql = str_replace('INSERT INTO', 'REPLACE INTO', $sql);

		$theDB->query($sql);

		//Now let's close it
		if($reOpenedDB){
			$theDB->close();
		}
	}

	public function _destroy($id){
		// Destroy the session, remove database rows
		$this->CI->db->where('session_id', $id);
		$this->CI->db->delete($this->sess_table_name);

		return TRUE;
	}

	public function _clean($max){
		// Remove expired rows
		srand(time());
		if ((rand() % 100) < $this->gc_probability)
		{
			$expire = $this->parent->now - $this->parent->sess_expiration;

			$this->CI->db->where("last_activity < {$expire}");
			$this->CI->db->delete($this->sess_table_name);

			log_message('debug', 'Session garbage collection performed.');
		}

		return TRUE;
	}

	public function _sess_gc(){
		$this->_clean($this->parent->sess_expiration);
	}
}
