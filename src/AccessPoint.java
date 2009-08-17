public class AccessPoint {
	// ||========== GLOBAL VARIABLES ==========||
	private String essid, bssid, enc, cipher, auth, key;
	private int channel;
	
	// ||========== CONTRUCTORS ==========||
	public AccessPoint(String essid, String bssid, int channel, String enc, String cipher, String auth, String key) {
		this.essid = essid;
		this.bssid = bssid;
		this.channel = channel;
		this.enc = enc;
		this.cipher = cipher;
		this.auth = auth;
		this.key = key;
	}
	
	// ||========== GETTERS/SETTERS ==========||
	public void setESSID(String essid) {
		this.essid = essid;
	}
	public String getESSID() {
		return essid;
	}
	public void setKey(String key) {
		this.key = key;
	}
	public String getKey() {
		return key;
	}
	public void setBSSID(String bssid) {
		this.bssid = bssid;
	}
	public String getBSSID() {
		return bssid;
	}
	public void setChannel(int channel) {
		this.channel = channel;
	}
	public int getChannel() {
		return channel;
	}
	public void setEnc(String enc) {
		this.enc = enc;
	}
	public String getEnc() {
		return enc;
	}
	public void setCipher(String cipher) {
		this.cipher = cipher;
	}
	public String getCipher() {
		return cipher;
	}
	public void setAuth(String auth) {
		this.auth = auth;
	}
	public String getAuth() {
		return auth;
	}
}