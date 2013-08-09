<?php

class Session_hybrid extends CI_Driver {

	protected $CI;

	protected $cookie_lifetime;
	protected $cookie_path;
	protected $cookie_domain;
	protected $cookie_secure;
	protected $cookie_httponly;

	protected $sess_table_name;

	protected $db_user_agent;
	protected $db_ip_address;
	protected $db_last_activity;

	public function __construct()
	{
		$this->CI = get_instance();

		session_set_save_handler(
			array($this, '_open'), array($this, '_close'),
			array($this, '_read'), array($this, '_write'),
			array($this, '_destroy'), array($this, '_clean')
		);

		foreach (array('sess_table_name', 'cookie_lifetime', 'cookie_path', 'cookie_domain', 'cookie_secure', 'cookie_httponly') as $key)
		{
			$this->$key = $this->CI->config->item($key) ?: (
				strpos($key, 'cookie_') === 0 ? ini_get("session.{$key}") : NULL
			);
		}
		session_set_cookie_params($this->cookie_lifetime,
			$this->cookie_path, $this->cookie_domain,
			$this->cookie_secure, $this->cookie_httponly
		);

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
		if ( ! is_array($session) OR ! isset($session['session_id']) OR ! isset($session['ip_address']) OR ! isset($session['user_agent']) OR ! isset($session['last_activity']))
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

		$_SESSION['session_id']	= session_id();
		$_SESSION['ip_address']	= $this->CI->input->ip_address();
		$_SESSION['user_agent']	= substr($this->CI->input->user_agent(), 0, 120);
		$_SESSION['last_activity'] = $this->parent->now;

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
		if (($this->parent->userdata['last_activity'] + $this->parent->sess_time_to_update) >= $this->parent->now)
		{
			return;
		}

		// Regenerate session id
		session_regenerate_id();

		// Update the session data in the session data array
		$this->parent->userdata['session_id'] = session_id();
		$this->parent->userdata['last_activity'] = $this->parent->now;
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
	 * Does nothing for native sessions
	 *
	 * @access private
	 * @return void
	 */
	public function _sess_gc(){}

	/**
	 * Session handling functions
	 */
	protected function _open(){
		// Are we using a database?  If so, load it
		if( !$this->sess_table_name ) {
			die('Session class database table name not configured');
		}
		$this->CI->load->database();

		return TRUE;
	}

	protected function _close(){
		// This function is intentionally left empty
	}

	protected function _read($id){
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

	protected function _write($id, $data){
		// Write session data into database
		$info = array(
			'session_id' => $id,
			'user_agent' => substr($this->CI->input->user_agent(), 0, 120),
			'ip_address' => $this->CI->input->ip_address(),
			'last_activity' => $this->parent ? $this->parent->now : time(),
			'user_data' => $data
		);

		$sql = $this->CI->db->insert_string($this->sess_table_name, $info);
		$sql = str_replace('INSERT INTO', 'REPLACE INTO', $sql);
		$this->CI->db->query($sql);
	}

	protected function _destroy($id){
		// Destroy the session, remove database rows
		$this->CI->db->where('session_id', $id);
		$this->CI->db->delete($this->sess_table_name);

		return TRUE;
	}

	protected function _clean($max){
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
}
