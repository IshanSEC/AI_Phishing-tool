export interface User {
  id: string;
  name: string;
  email: string;
  role: 'admin' | 'user';
  created_at?: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}

export interface XAIIndicator {
  category?: string;
  indicator?: string;
  severity: 'Low' | 'Medium' | 'High';
  matches: string[];
  description?: string;
  explanation?: string;
}

export interface DNSRecords {
  has_dns: boolean;
  spf_record: string | null;
  dmarc_record: string | null;
  resolved_ips: string[];
}

export interface LinkDetail {
  url: string;
  domain: string;
  resolved_ips: string[];
  has_dns: boolean;
}

export interface EmailScanDetails {
  subject: string;
  sender_name: string;
  sender_email: string;
  sender_domain: string;
  suspicious_domain: boolean;
  possible_spoofing: boolean;
  mismatched_reply_to: boolean;
  reply_to: string;
  spf_pass: boolean;
  dkim_pass: boolean;
  xai_indicators: XAIIndicator[];
  prediction: 'Phishing' | 'Legitimate';
  confidence: number;
  risk_score: number;
  threat_level: 'Low' | 'Medium' | 'High';
  timestamp: string;
  dns_records?: DNSRecords;
  link_details?: LinkDetail[];
}

export interface PasswordAuditResponse {
  entropy_bits: number;
  strength: 'Very Weak' | 'Weak' | 'Medium' | 'Strong';
  color: 'red' | 'orange' | 'yellow' | 'green';
  is_leaked: boolean;
  leak_count: number;
  recommendations: string[];
}

export interface FileMetadata {
  file_name: string;
  file_size: number;
  md5: string;
  sha256: string;
  detected_type: string;
  extension_mismatch: boolean;
  mismatch_warning: string;
  rtlo_detected: boolean;
  double_ext: boolean;
  double_ext_warning: string;
  compilation_time: string;
  architecture: string;
  num_sections: number | string;
  sections: string[];
  analysis_time: string;
}

export interface FileScanDetails {
  prediction: 'Safe' | 'Suspicious' | 'Malicious';
  threat_level: 'Low' | 'Medium' | 'High';
  risk_score: number;
  metadata: FileMetadata;
  xai_indicators: XAIIndicator[];
}

export interface ScanRecord {
  id: string;
  user_id: string;
  type: 'email' | 'file';
  name: string;
  input_content: string;
  prediction: string;
  confidence: number;
  risk_score: number;
  details: EmailScanDetails | FileScanDetails;
  created_at: string;
}

export interface SystemLog {
  id: string;
  level: 'INFO' | 'WARNING' | 'ERROR';
  message: string;
  timestamp: string;
}

export interface AdminStats {
  summary: {
    total_scans: number;
    phishing_scans: number;
    legitimate_scans: number;
    email_scans: number;
    file_scans: number;
    average_risk_score: number;
  };
  logs: SystemLog[];
  model_diagnostics: {
    loaded: boolean;
    algorithm: string;
    features_count: number;
  };
}
