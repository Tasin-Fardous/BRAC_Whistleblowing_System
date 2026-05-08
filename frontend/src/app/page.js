"use client";
import React, { useState, useEffect } from 'react';

const API_URL = "http://127.0.0.1:8000";

export default function Home() {
  const [view, setView] = useState('login'); 
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);

  const authFetch = async (path, options = {}) => {
    const headers = { 'Content-Type': 'application/json', ...options.headers };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${API_URL}${path}`, { ...options, headers });
    return res;
  };

  const renderView = () => {
    if (!token) {
      if (view === 'register') return <Register setView={setView} authFetch={authFetch} />;
      return <Login setView={setView} setUser={setUser} setToken={setToken} authFetch={authFetch} />;
    }
    
    // STRICT ROLE ENFORCEMENT
    if (user.role === 'reporter') return <ReporterDashboard user={user} authFetch={authFetch} />;
    if (user.role === 'admin') return <AdminDashboard user={user} authFetch={authFetch} />;
    if (user.role === 'auditor') return <AuditorDashboard user={user} authFetch={authFetch} />;
    
    return <Login setView={setView} setUser={setUser} setToken={setToken} authFetch={authFetch} />;
  };

  return (
    <>
      <nav className="navbar fade-in">
        <div className="logo">BRAC Secure Whistleblowing</div>
        {user && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
            <span style={{ marginLeft: '10px' }}>Logged in as: <strong>{user.email}</strong> ({user.role})</span>
            <button className="btn btn-secondary" onClick={() => { setUser(null); setToken(null); setView('login'); }}>Logout</button>
          </div>
        )}
      </nav>
      <div className="container fade-in">
        {renderView()}
      </div>
    </>
  );
}

function Login({ setView, setUser, setToken, authFetch }) {
  const [data, setData] = useState({ email: '', password: '', otp: '' });
  const [otpSent, setOtpSent] = useState(false);
  const [error, setError] = useState('');

  const sendOtp = async () => {
    if (!data.email) return alert("Please enter email first");
    const res = await fetch(`${API_URL}/2fa/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: data.email })
    });
    if (res.ok) {
      setOtpSent(true);
      alert("Verification code sent! Check your email (and server console).");
    } else {
      alert("Failed to send OTP. Check if email is correct.");
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    const res = await fetch(`${API_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    const d = await res.json();
    if (res.ok) {
      setToken(d.token);
      setUser({ email: d.email, role: d.role });
      localStorage.setItem('token', d.token);
    } else {
      setError(d.detail || "Login failed");
    }
  };

  return (
    <div className="glass-panel fade-in" style={{maxWidth: '400px', margin: '40px auto'}}>
      <h2>Secure Login</h2>
      {error && <p style={{color: '#ff4444', marginBottom: '15px'}}>{error}</p>}
      <form onSubmit={handleLogin}>
        <input type="email" placeholder="BRACU Email" value={data.email} onChange={e => setData({...data, email: e.target.value})} required />
        <input type="password" placeholder="Password" value={data.password} onChange={e => setData({...data, password: e.target.value})} required />
        
        <div style={{display: 'flex', gap: '10px', marginTop: '10px'}}>
          <input type="text" placeholder="6-digit OTP" value={data.otp} onChange={e => setData({...data, otp: e.target.value})} required />
          <button type="button" className="btn btn-secondary" onClick={sendOtp} style={{flexShrink: 0, padding: '5px 10px', fontSize: '0.85em'}}>{otpSent ? "Resend" : "Send OTP"}</button>
        </div>
        
        <button type="submit" className="btn" style={{marginTop: '20px', width: '100%'}}>Login to Secure Portal</button>
      </form>
      <p style={{marginTop: '20px', textAlign: 'center'}}>
        New whistleblower? <a href="#" style={{color: 'var(--accent-color)', textDecoration: 'none'}} onClick={(e) => { e.preventDefault(); setView('register'); }}>Register here</a>
      </p>
    </div>
  );
}

function Register({ setView, authFetch }) {
  const [role, setRole] = useState('reporter');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [sName, setSName] = useState('');
  const [sId, setSId] = useState('');
  const [sContact, setSContact] = useState('');
  const [pName, setPName] = useState('');
  const [pId, setPId] = useState('');
  const [msg, setMsg] = useState('');
  const [error, setError] = useState('');

  const handleRegister = async () => {
    setError(''); setMsg('');
    const payload = { role, email, password };
    if (role === 'reporter') {
      payload.student_name = sName; payload.student_id = sId; payload.student_contact = sContact;
    } else {
      payload.proctor_name = pName; payload.proctor_id = pId;
    }
    
    const res = await authFetch('/register', { method: 'POST', body: JSON.stringify(payload) });
    const data = await res.json();
    if (res.ok) {
      setMsg("Successfully registered! You can now login.");
      setTimeout(() => setView('login'), 2000);
    } else {
      setError(data.detail || "Error");
    }
  };

  return (
    <div className="glass-panel fade-in" style={{ maxWidth: '500px', margin: '0 auto', marginTop: '40px' }}>
      <h2>Register Secure Profile</h2>
      {msg && <p style={{color: '#00ff00'}}>{msg}</p>}
      {error && <p style={{color: '#ff4444'}}>{error}</p>}
      
      <select value={role} onChange={(e) => setRole(e.target.value)}>
        <option value="reporter">Student (Reporter)</option>
        <option value="auditor">Proctor (Auditor)</option>
      </select>
      <input type="password" placeholder="Strong Password" value={password} onChange={e=>setPassword(e.target.value)} />

      {role === 'reporter' ? (
        <div style={{ padding: '15px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)', marginBottom: '15px' }}>
          <h4 style={{marginTop: 0, marginBottom: '10px'}}>Student Details</h4>
          <input type="email" placeholder="G Suite Email (*@g.bracu.ac.bd)" value={email} onChange={e=>setEmail(e.target.value)} />
          <input type="text" placeholder="Student Name" value={sName} onChange={e=>setSName(e.target.value)} />
          <input type="text" placeholder="Student ID" value={sId} onChange={e=>setSId(e.target.value)} />
          <input type="text" placeholder="Contact No" value={sContact} onChange={e=>setSContact(e.target.value)} style={{marginBottom: 0}} />
        </div>
      ) : (
        <div style={{ padding: '15px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.1)', marginBottom: '15px' }}>
          <h4 style={{marginTop: 0, marginBottom: '10px'}}>Proctor Details</h4>
          <input type="email" placeholder="Work Email (*@bracu.ac.bd)" value={email} onChange={e=>setEmail(e.target.value)} />
          <input type="text" placeholder="Proctor Name" value={pName} onChange={e=>setPName(e.target.value)} />
          <input type="text" placeholder="Proctor ID (e.g. EMP100)" value={pId} onChange={e=>setPId(e.target.value)} style={{marginBottom: 0}} />
        </div>
      )}
      <button className="btn" style={{width: '100%', marginBottom: '15px'}} onClick={handleRegister}>Generate Keys & Register</button>
      <div style={{textAlign: 'center'}}>
        <a href="#" style={{color: 'var(--accent-color)', fontSize: '0.9em', textDecoration: 'none'}} onClick={(e) => { e.preventDefault(); setView('login'); }}>Already registered? Login</a>
      </div>
    </div>
  );
}

function DecryptViewer({ content }) {
  const [revealed, setRevealed] = useState(false);
  
  // Reset if content changes
  useEffect(() => setRevealed(false), [content]);

  if (!revealed) {
    return (
      <div style={{background: 'rgba(255,255,255,0.02)', padding: '15px', borderRadius: '8px', borderLeft: '3px solid var(--accent-color)', marginTop: '5px', textAlign: 'center'}}>
        <p style={{fontFamily: 'monospace', color: 'var(--text-muted)', margin: '0 0 10px 0'}}>**************************<br/>ENCRYPTED PAYLOAD<br/>**************************</p>
        <button className="btn btn-secondary" onClick={() => setRevealed(true)} style={{fontSize: '0.85em', padding: '5px 15px'}}>Decrypt & View Content</button>
      </div>
    );
  }

  return (
    <div style={{background: 'rgba(255,255,255,0.02)', padding: '15px', borderRadius: '8px', borderLeft: '3px solid #00cc66', marginTop: '5px', whiteSpace: 'pre-wrap'}}>
      {content}
    </div>
  );
}

function ProfileEditor({ authFetch, user, profile, setProfile }) {
  const [editMode, setEditMode] = useState(false);
  const [data, setData] = useState({ name: '', id: '', contact: '', email: '' });
  const [msg, setMsg] = useState('');

  useEffect(() => {
    if (!profile || profile === "N/A") return;
    const parts = profile.split(', ');
    const parsed = { name: '', id: '', contact: '', email: '' };
    parts.forEach(p => {
      if(p.startsWith('Name: ')) parsed.name = p.replace('Name: ', '');
      if(p.startsWith('ID: ') || p.startsWith('Proctor ID: ')) parsed.id = p.split(': ')[1];
      if(p.startsWith('Contact: ')) parsed.contact = p.replace('Contact: ', '');
      if(p.startsWith('Email: ')) parsed.email = p.replace('Email: ', '');
    });
    setData(parsed);
  }, [profile]);

  const handleSave = async () => {
    setMsg('');
    let newStr = "";
    if (user.role === 'reporter') {
      newStr = `Name: ${data.name}, ID: ${data.id}, Contact: ${data.contact}, Email: ${data.email}`;
    } else {
      newStr = `Name: ${data.name}, Proctor ID: ${data.id}, Email: ${data.email}`;
    }
    
    const res = await authFetch('/users/profile', { 
      method: 'PUT', 
      body: JSON.stringify({ profile_data: newStr, new_email: data.email }) 
    });
    if(res.ok) {
       setProfile(newStr);
       setEditMode(false);
       setMsg("Profile updated and re-encrypted successfully!");
    } else {
       const err = await res.json();
       setMsg(err.detail || "Update failed");
    }
  };

  if (!editMode) {
    return (
      <div style={{ marginTop: '20px' }}>
        {msg && <p style={{color: '#00ff00'}}>{msg}</p>}
        <button className="btn btn-secondary" onClick={() => setEditMode(true)}>Edit Profile Data</button>
      </div>
    );
  }

  return (
    <div style={{ marginTop: '20px', padding: '15px', background: 'rgba(255,255,255,0.05)', borderRadius: '8px' }}>
      <h4 style={{marginTop: 0}}>Update Identity</h4>
      {msg && <p style={{color: '#ff4444'}}>{msg}</p>}
      <input type="text" placeholder="Name" value={data.name} onChange={e=>setData({...data, name: e.target.value})} style={{marginBottom: '10px'}}/>
      <input type="text" placeholder="ID" value={data.id} onChange={e=>setData({...data, id: e.target.value})} style={{marginBottom: '10px'}}/>
      {user.role === 'reporter' && (
        <input type="text" placeholder="Contact" value={data.contact} onChange={e=>setData({...data, contact: e.target.value})} style={{marginBottom: '10px'}}/>
      )}
      <input type="email" placeholder="Email" value={data.email} onChange={e=>setData({...data, email: e.target.value})} style={{marginBottom: '10px'}}/>
      <div style={{display: 'flex', gap: '10px'}}>
        <button className="btn" onClick={handleSave}>Save & Encrypt</button>
        <button className="btn btn-secondary" onClick={() => setEditMode(false)}>Cancel</button>
      </div>
    </div>
  );
}

function ReporterDashboard({ user, authFetch }) {
  const [profile, setProfile] = useState('Loading...');
  const [content, setContent] = useState('');
  const [attachment, setAttachment] = useState('');
  const [msg, setMsg] = useState('');
  const [reports, setReports] = useState([]);

  const fetchReports = async () => {
    const res = await authFetch('/reports');
    if(res.ok) setReports(await res.json());
  };

  useEffect(() => {
    authFetch('/users/profile').then(r=>r.json()).then(d => setProfile(d.profile_data || "N/A"));
    fetchReports();
  }, []);

  const handleFile = (e) => {
    const file = e.target.files[0];
    if(!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setAttachment(ev.target.result);
    reader.readAsDataURL(file);
  };

  const submit = async () => {
    const res = await authFetch('/reports', {
      method: 'POST', body: JSON.stringify({ report_content: content, attachment_data: attachment || null })
    });
    if(res.ok) {
      setMsg("Report and evidence securely mathematically encrypted and submitted!");
      setContent(''); setAttachment('');
      fetchReports();
    }
  };

  return (
    <div className="dashboard-grid fade-in">
      <div className="glass-panel">
        <h3>Submit Secure Report</h3>
        {msg && <p style={{color: '#00ff00', background: 'rgba(0,255,0,0.1)', padding: '10px', borderRadius: '8px'}}>{msg}</p>}
        <textarea rows="6" placeholder="Describe the incident securely..." value={content} onChange={e=>setContent(e.target.value)}></textarea>
        
        <div style={{ marginTop: '10px', marginBottom: '15px', padding: '10px', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
          <label style={{display: 'block', marginBottom: '8px', fontSize: '0.9em', color: 'var(--text-muted)'}}>Optional Evidence (Doc/PDF/Image/Video/Audio)</label>
          <input type="file" onChange={handleFile} style={{marginBottom: 0, padding: '8px', background: 'transparent', border: '1px dashed var(--accent-color)'}} />
        </div>
        <button className="btn" onClick={submit}>Encrypt & Submit</button>

        <h4 style={{marginTop: '30px'}}>Your Previous Reports</h4>
        {reports.length === 0 ? <p>No reports submitted.</p> : reports.map(r => (
          <div key={r.id} style={{padding: '10px', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '8px', marginTop: '10px'}}>
            <span style={{float: 'right', background: 'rgba(0, 229, 255, 0.2)', color: 'var(--accent-color)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.8em'}}>
              {r.status.toUpperCase()}
            </span>
            <strong>Report #{r.id}</strong>
          </div>
        ))}

      </div>
      <div className="glass-panel">
        <h3>Your Secure Profile</h3>
        <p style={{color: 'var(--text-muted)'}}>Decrypted Profile Data:</p>
        <div style={{ background: 'rgba(0,0,0,0.3)', padding: '15px', borderRadius: '8px', wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.9em' }}>
          {profile.split(',').map((p, i) => <div key={i}>{p}</div>)}
        </div>
        <ProfileEditor authFetch={authFetch} user={user} profile={profile} setProfile={setProfile} />
      </div>
    </div>
  );
}

function AdminDashboard({ authFetch }) {
  const [reports, setReports] = useState([]);
  const [auditors, setAuditors] = useState([]);
  const [reporters, setReporters] = useState([]);
  const [selectedReport, setSelectedReport] = useState(null);
  const [activeTab, setActiveTab] = useState('reports');

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    const r = await authFetch('/reports').then(res => res.json());
    setReports(r);
    const a = await authFetch('/auditors').then(res => res.json());
    setAuditors(a);
    const rep = await authFetch('/reporters').then(res => res.json());
    setReporters(rep);
  };

  const assign = async (reportId, auditorId) => {
    if (!auditorId) return;
    await authFetch('/reports/assign', {
      method: 'POST', body: JSON.stringify({ report_id: reportId, auditor_id: parseInt(auditorId) })
    });
    fetchData();
  };

  const makeDecision = async (reportId, decision) => {
    if (!decision) return;
    await authFetch(`/reports/${reportId}/decision`, {
      method: 'POST', body: JSON.stringify({ decision })
    });
    fetchData();
  };

  if (selectedReport) {
    const r = reports.find(x => x.id === selectedReport);
    if (!r) { setSelectedReport(null); return null; }
    
    return (
      <div className="glass-panel fade-in">
        <button className="btn btn-secondary" onClick={() => setSelectedReport(null)} style={{marginBottom: '20px'}}>← Back to List</button>
        <h3>Report #{r.id} Details</h3>
        
        <div style={{marginBottom: '15px'}}>
          <strong>Status: </strong> <span style={{background: 'rgba(0, 229, 255, 0.2)', color: 'var(--accent-color)', padding: '4px 8px', borderRadius: '4px'}}>{r.status.toUpperCase()}</span>
        </div>
        
        <div style={{marginBottom: '15px'}}>
          <strong>Reporter Identity Details:</strong>
          <div style={{background: 'rgba(255,255,255,0.02)', padding: '10px', borderRadius: '8px', borderLeft: '3px solid var(--accent-color)', marginTop: '5px'}}>
            {r.reporter_profile || 'Unknown'}
          </div>
        </div>

        <div style={{marginBottom: '15px'}}>
          <strong>Decrypted Report Content:</strong>
          <DecryptViewer content={r.decrypted_content} />
        </div>

        {r.has_attachment && (
          <div style={{marginBottom: '15px'}}>
            <strong>Attached Evidence:</strong> <span style={{color: '#00ff00'}}>Securely Attached</span>
            <br/>
            <button className="btn btn-secondary" style={{marginTop: '10px', fontSize: '0.8em', padding: '6px 12px'}} onClick={async (e) => {
              e.target.innerText = "Decrypting (Math Heavy)...";
              try {
                const aRes = await authFetch(`/reports/${r.id}/attachment`).then(res => res.json());
                if (aRes.attachment) {
                  const a = document.createElement("a");
                  a.href = aRes.attachment;
                  a.download = `Evidence_Report_${r.id}`;
                  a.click();
                }
              } catch (err) {
                alert("Failed to decrypt attachment.");
              }
              e.target.innerText = "Download Decrypted Attachment";
            }}>
              Download Decrypted Attachment
            </button>
          </div>
        )}

        {r.auditor_feedback && (
          <div style={{marginBottom: '15px'}}>
            <strong>Auditor Validation Feedback:</strong>
            <div style={{background: 'rgba(255,255,255,0.02)', padding: '15px', borderRadius: '8px', borderLeft: '3px solid #ffaa00', marginTop: '5px', fontStyle: 'italic'}}>
              "{r.auditor_feedback}"
            </div>
          </div>
        )}

        <hr style={{borderColor: 'var(--border-color)', margin: '20px 0'}} />

        {r.status === 'pending' && (
          <div>
            <h4>Assign to Proctor (Auditor)</h4>
            <div style={{display: 'flex', gap: '10px'}}>
              <select id={`sel-${r.id}`} style={{marginBottom: 0, padding: '10px', width: '350px'}}>
                <option value="">Select Proctor...</option>
                {auditors.map(a => <option key={a.id} value={a.id}>{a.profile}</option>)}
              </select>
              <button className="btn" onClick={() => {
                assign(r.id, document.getElementById(`sel-${r.id}`).value);
                setSelectedReport(null);
              }}>Assign securely</button>
            </div>
          </div>
        )}

        {r.status === 'validated' && (
          <div>
            <h4>Make Final Administrative Decision</h4>
            <div style={{display: 'flex', gap: '10px'}}>
              <select id={`dec-${r.id}`} style={{marginBottom: 0, padding: '10px', width: '200px'}}>
                <option value="">Select Decision...</option>
                <option value="approved">Approve</option>
                <option value="rejected">Reject</option>
                <option value="need more information">Need More Info</option>
              </select>
              <button className="btn" style={{background: 'var(--accent-color)', color: '#000'}} onClick={() => {
                makeDecision(r.id, document.getElementById(`dec-${r.id}`).value);
                setSelectedReport(null);
              }}>Submit Final Decision</button>
            </div>
          </div>
        )}

      </div>
    );
  }

  return (
    <div className="glass-panel fade-in">
      <h3>Admin Operations Dashboard</h3>
      
      <div style={{display: 'flex', gap: '10px', marginBottom: '20px'}}>
        <button className={`btn ${activeTab === 'reports' ? '' : 'btn-secondary'}`} onClick={() => setActiveTab('reports')}>View Reports</button>
        <button className={`btn ${activeTab === 'auditors' ? '' : 'btn-secondary'}`} onClick={() => setActiveTab('auditors')}>View Auditors</button>
        <button className={`btn ${activeTab === 'reporters' ? '' : 'btn-secondary'}`} onClick={() => setActiveTab('reporters')}>View Reporters</button>
      </div>

      {activeTab === 'reports' && (
        <div style={{overflowX: 'auto'}}>
          <table style={{width: '100%', textAlign: 'left', borderCollapse: 'collapse', marginTop: '10px'}}>
            <thead>
              <tr style={{borderBottom: '1px solid var(--border-color)'}}>
                <th style={{padding: '10px'}}>Report ID</th>
                <th style={{padding: '10px'}}>Status</th>
                <th style={{padding: '10px'}}>Action</th>
              </tr>
            </thead>
            <tbody>
              {reports.map(r => (
                <tr key={r.id} style={{borderBottom: '1px solid rgba(255,255,255,0.05)'}}>
                  <td style={{padding: '10px'}}>#{r.id}</td>
                  <td style={{padding: '10px'}}>
                    <strong style={{color: r.status === 'validated' ? '#00ff00' : 'inherit'}}>{r.status}</strong>
                  </td>
                  <td style={{padding: '10px'}}>
                    <button className="btn btn-secondary" style={{padding: '5px 15px'}} onClick={() => setSelectedReport(r.id)}>View Details</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'auditors' && (
        <div style={{overflowX: 'auto'}}>
          <table style={{width: '100%', textAlign: 'left', borderCollapse: 'collapse', marginTop: '10px'}}>
            <thead>
              <tr style={{borderBottom: '1px solid var(--border-color)'}}>
                <th style={{padding: '10px'}}>Proctor ID</th>
                <th style={{padding: '10px'}}>Decrypted Proctor Details</th>
              </tr>
            </thead>
            <tbody>
              {auditors.map(a => (
                <tr key={a.id} style={{borderBottom: '1px solid rgba(255,255,255,0.05)'}}>
                  <td style={{padding: '10px'}}>#{a.id}</td>
                  <td style={{padding: '10px', fontSize: '0.9em'}}>{a.profile}</td>
                </tr>
              ))}
              {auditors.length === 0 && (
                <tr>
                  <td colSpan="2" style={{padding: '10px'}}>No Proctors registered yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'reporters' && (
        <div style={{overflowX: 'auto'}}>
          <table style={{width: '100%', textAlign: 'left', borderCollapse: 'collapse', marginTop: '10px'}}>
            <thead>
              <tr style={{borderBottom: '1px solid var(--border-color)'}}>
                <th style={{padding: '10px'}}>Student ID</th>
                <th style={{padding: '10px'}}>Decrypted Reporter Details</th>
              </tr>
            </thead>
            <tbody>
              {reporters.map(r => (
                <tr key={r.id} style={{borderBottom: '1px solid rgba(255,255,255,0.05)'}}>
                  <td style={{padding: '10px'}}>#{r.id}</td>
                  <td style={{padding: '10px', fontSize: '0.9em'}}>{r.profile}</td>
                </tr>
              ))}
              {reporters.length === 0 && (
                <tr>
                  <td colSpan="2" style={{padding: '10px'}}>No Reporters registered yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function AuditorDashboard({ user, authFetch }) {
  const [reports, setReports] = useState([]);
  const [feedbacks, setFeedbacks] = useState({});
  const [profile, setProfile] = useState('Loading...');

  useEffect(() => {
    fetchData();
    authFetch('/users/profile').then(r=>r.json()).then(d => setProfile(d.profile_data || "N/A"));
  }, []);

  const fetchData = async () => {
    authFetch('/reports').then(r=>r.json()).then(setReports);
  }

  const downloadFile = (base64Str, id) => {
    const a = document.createElement("a");
    a.href = base64Str;
    a.download = `Evidence_Report_${id}`;
    a.click();
  };

  const validateReport = async (id) => {
    const fb = feedbacks[id] || "No feedback provided";
    await authFetch(`/reports/${id}/validate`, { method: 'POST', body: JSON.stringify({ feedback: fb }) });
    fetchData();
  };

  return (
    <div className="fade-in" style={{ maxWidth: '800px', margin: '0 auto' }}>
      <div className="glass-panel" style={{marginBottom: '20px'}}>
        <h3>Your Secure Profile</h3>
        <div style={{ background: 'rgba(0,0,0,0.3)', padding: '15px', borderRadius: '8px', wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.9em' }}>
          {profile.split(',').map((p, i) => <div key={i}>{p}</div>)}
        </div>
        <ProfileEditor authFetch={authFetch} user={user} profile={profile} setProfile={setProfile} />
      </div>

      <div className="glass-panel">
        <h3>Auditor (Proctor) Review Panel</h3>
        <p style={{color: 'var(--text-muted)'}}>View reports assigned to you. Reporter identities are cryptographically stripped.</p>
      
      {reports.length === 0 ? <p>No reports assigned to you yet.</p> : reports.map(r => (
        <div key={r.id} style={{marginTop: '20px', padding: '20px', border: '1px solid var(--border-color)', borderRadius: '12px', background: 'rgba(0,0,0,0.2)'}}>
          <div style={{display: 'flex', justifyContent: 'space-between', marginBottom: '15px'}}>
            <h4 style={{margin: 0}}>Case #{r.id}</h4>
            <span style={{background: 'rgba(0, 229, 255, 0.2)', color: 'var(--accent-color)', padding: '4px 8px', borderRadius: '4px', fontSize: '0.8em'}}>{r.status.toUpperCase()}</span>
          </div>
          <div style={{marginBottom: '15px'}}>
            <strong>Decrypted Report Content:</strong>
            <DecryptViewer content={r.decrypted_content} />
          </div>
          
          {r.has_attachment && (
            <div style={{marginBottom: '15px'}}>
              <h5 style={{margin: '0 0 5px 0', color: 'var(--text-muted)'}}>Decrypted Attachments</h5>
              <button className="btn btn-secondary" style={{fontSize: '0.8em', padding: '6px 12px'}} onClick={async (e) => {
                e.target.innerText = "Decrypting (Math Heavy)...";
                try {
                  const aRes = await authFetch(`/reports/${r.id}/attachment`).then(res => res.json());
                  if (aRes.attachment) {
                    const a = document.createElement("a");
                    a.href = aRes.attachment;
                    a.download = `Evidence_Report_${r.id}`;
                    a.click();
                  }
                } catch (err) {
                  alert("Failed to decrypt attachment.");
                }
                e.target.innerText = "Download Base64 Evidence File";
              }}>
                Download Base64 Evidence File
              </button>
            </div>
          )}

          {r.status === 'assigned' && (
            <div style={{marginTop: '15px'}}>
              <textarea 
                rows="3" 
                placeholder="Enter validation feedback for Admin..." 
                value={feedbacks[r.id] || ''} 
                onChange={e => setFeedbacks({...feedbacks, [r.id]: e.target.value})}
                style={{marginBottom: '10px'}}
              />
              <button className="btn" style={{background: '#00cc66', color: '#fff', width: '100%'}} onClick={() => validateReport(r.id)}>
                ✓ Submit Feedback & Validate
              </button>
            </div>
          )}
          
          <div style={{ marginTop: '15px', padding: '12px', borderRadius: '8px', background: 'rgba(255, 60, 60, 0.1)', border: '1px solid rgba(255, 60, 60, 0.2)', display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{fontSize: '1.2em'}}>🔒</span>
            <p style={{margin: 0, color: '#ff6b6b', fontSize: '0.9em'}}>
              <strong>Identity Withheld:</strong> Separation of duties enforced. The reporter's identity data is mathematically inaccessible to the Auditor.
            </p>
          </div>
        </div>
      ))}
      </div>
    </div>
  );
}
