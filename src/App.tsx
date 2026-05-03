import React, { useState, useEffect, useMemo } from 'react';
import { 
  Shield, Search, Filter, Bell, Download, 
  BarChart3, Globe, Building2, Terminal, 
  AlertTriangle, CheckCircle2, Info, 
  ChevronRight, LogIn, LogOut, User,
  ExternalLink, MousePointer2, AlertCircle
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  collection, query, onSnapshot, addDoc, doc, updateDoc, deleteDoc,
  orderBy, limit as limitFirestore, Timestamp, where, getDocs
} from 'firebase/firestore';
import { onAuthStateChanged, User as FirebaseUser } from 'firebase/auth';
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, 
  Tooltip, ResponsiveContainer
} from 'recharts';

import { db, auth, signIn, handleFirestoreError } from './lib/firebase';
import { Threat, ActorProfile, Alert, Source, OperationType } from './types';
import { searchThreats, getActorProfile, generateThreatIoCs } from './services/geminiService';
import { REGIONS, VERTICALS, SEVERITY_COLORS } from './constants';
import { cn, formatDate } from './lib/utils';

export default function App() {
  const [user, setUser] = useState<FirebaseUser | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [sources, setSources] = useState<Source[]>([]);
  const [newSourceName, setNewSourceName] = useState('');
  const [newSourceUrl, setNewSourceUrl] = useState('');
  const [loading, setLoading] = useState(true);
  const [searching, setSearching] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRegion, setSelectedRegion] = useState('Global');
  const [selectedVertical, setSelectedVertical] = useState('All');
  const [domainFilter, setDomainFilter] = useState('');
  const [notifications, setNotifications] = useState<string[]>([]);
  const [creatingAlert, setCreatingAlert] = useState(false);
  const [alertRegion, setAlertRegion] = useState('Global');
  const [alertVertical, setAlertVertical] = useState('All');
  const [alertKeywords, setAlertKeywords] = useState('');
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);
  const [actorProfile, setActorProfile] = useState<ActorProfile | null>(null);

  // Auth Listener
  useEffect(() => {
    return onAuthStateChanged(auth, (u) => {
      setUser(u);
      setLoading(false);
    });
  }, []);

  // Real-time Listeners
  useEffect(() => {
    if (!user) return;

    const qTh = query(collection(db, 'threats'), orderBy('publishedAt', 'desc'), limitFirestore(50));
    const unsubscribeThreats = onSnapshot(qTh, (snapshot) => {
      const data = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as Threat));
      
      // Check for notifications based on alerts
      alerts.forEach(alert => {
        data.forEach(threat => {
          if ((alert.filters.region === 'Global' || threat.region === alert.filters.region) &&
              (alert.filters.vertical === 'All' || threat.vertical === alert.filters.vertical) &&
              ((alert.filters.keywords || []).length === 0 || (alert.filters.keywords || []).some(kw => threat.title.includes(kw) || threat.summary.includes(kw)))) {
             setNotifications(prev => [`Alert match for ${threat.title}`, ...prev]);
          }
        });
      });
      
      setThreats(data);
    }, (error) => handleFirestoreError(error, OperationType.LIST, 'threats'));

    const qAl = query(collection(db, 'alerts'), where('userId', '==', user.uid));
    const unsubscribeAlerts = onSnapshot(qAl, (snapshot) => {
      setAlerts(snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as Alert)));
    }, (error) => handleFirestoreError(error, OperationType.LIST, 'alerts'));

    const qSo = query(collection(db, 'sources'));
    const unsubscribeSources = onSnapshot(qSo, (snapshot) => {
        setSources(snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() } as Source)));
    }, (error) => handleFirestoreError(error, OperationType.LIST, 'sources'));

    return () => {
        unsubscribeThreats();
        unsubscribeAlerts();
        unsubscribeSources();
    };
  }, [user]);

  const addSource = async () => {
      if (!newSourceName || !newSourceUrl) return;
      try {
          await addDoc(collection(db, 'sources'), { name: newSourceName, url: newSourceUrl });
          setNewSourceName('');
          setNewSourceUrl('');
      } catch (error) {
          handleFirestoreError(error, OperationType.CREATE, 'sources');
      }
  };

  const deleteSource = async (id: string) => {
      try {
          await deleteDoc(doc(db, 'sources', id));
      } catch (error) {
          handleFirestoreError(error, OperationType.DELETE, 'sources');
      }
  };

  const filteredThreats = useMemo(() => {
    return threats.filter(t => {
      const matchesRegion = selectedRegion === 'Global' || t.region === selectedRegion;
      const matchesVertical = selectedVertical === 'All' || t.vertical === selectedVertical;
      const matchesDomain = !domainFilter || (t.domain && t.domain.toLowerCase().includes(domainFilter.toLowerCase()));
      const matchesQuery = !searchQuery || 
        t.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        t.summary.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesRegion && matchesVertical && matchesDomain && matchesQuery;
    });
  }, [threats, selectedRegion, selectedVertical, searchQuery, domainFilter]);

  const handleSearch = async () => {
    if (!searchQuery && selectedRegion === 'Global' && selectedVertical === 'All') return;
    setSearching(true);
    try {
      const results = await searchThreats(searchQuery, selectedRegion, selectedVertical, domainFilter);
      
      // Add results to Firestore for real-time sync across clients
      for (const res of results) {
        if (!res.title) continue;
        
        // Basic deduplication
        const exists = threats.some(t => t.title === res.title);
        if (!exists) {
          await addDoc(collection(db, 'threats'), {
            ...res,
            publishedAt: Timestamp.now(),
            domain: res.sourceUrl ? new URL(res.sourceUrl).hostname : ''
          });
        }
      }
    } catch (error) {
      console.error("Search error:", error);
    } finally {
      setSearching(false);
    }
  };

  const downloadIoCs = (threat: Threat) => {
    if (!threat.iocs || threat.iocs.length === 0) return;
    
    const headers = ['Type', 'Value', 'Actor', 'Threat Title'];
    const rows = threat.iocs.map(ioc => [
      ioc.type,
      ioc.value,
      ioc.actor || 'Unknown',
      `"${threat.title}"`
    ]);
    
    const csvContent = [headers, ...rows].map(e => e.join(",")).join("\n");
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", `iocs_${threat.id}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleViewActor = async (actorName: string) => {
    try {
      // Check if we have it in Firestore first
      const q = query(collection(db, 'profiles'), where('name', '==', actorName));
      const snap = await getDocs(q);
      
      if (!snap.empty) {
        setActorProfile({ id: snap.docs[0].id, ...snap.docs[0].data() } as ActorProfile);
      } else {
        // Get from Gemini and potentially save
        const profile = await getActorProfile(actorName);
        const newActor = { ...profile, name: actorName, lastSeen: Timestamp.now() } as ActorProfile;
        setActorProfile(newActor as any);
        await addDoc(collection(db, 'profiles'), newActor);
      }
    } catch (error) {
      console.error("Error viewing actor:", error);
    }
  };

  const handleGenerateIoCs = async (threat: Threat) => {
    try {
      const newIocs = await generateThreatIoCs(threat.title, threat.summary);
      const threatRef = doc(db, 'threats', threat.id);
      await updateDoc(threatRef, {
        iocs: [...(threat.iocs || []), ...newIocs]
      });
    } catch (error) {
       console.error("Error generating IoCs:", error);
    }
  };

  const trendsData = useMemo(() => {
    const counts: Record<string, number> = {};
    threats.forEach(t => {
      counts[t.vertical] = (counts[t.vertical] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [threats]);

  if (loading) {
    return (
      <div className="h-screen w-full flex items-center justify-center bg-dash-bg">
        <div className="flex flex-col items-center gap-4">
          <Shield className="w-12 h-12 text-dash-ink animate-spin" />
          <p className="font-mono text-xs uppercase tracking-widest animate-pulse">Initializing Neural Link...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="h-screen w-full flex items-center justify-center bg-dash-bg p-6">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-md w-full bg-white border border-dash-ink p-8 shadow-[8px_8px_0px_0px_rgba(20,20,20,1)] flex flex-col items-center text-center gap-6"
        >
          <div className="p-4 bg-dash-ink rounded-full">
            <Shield className="w-12 h-12 text-dash-bg" />
          </div>
          <div>
            <h1 className="text-3xl font-bold tracking-tighter uppercase mb-2">ThreatRadar Intelligence</h1>
            <p className="text-sm text-neutral-500 font-medium">Access public source threat intelligence, visualize trends, and export IoCs. Secure neural link required.</p>
          </div>
          <button 
            onClick={signIn}
            className="w-full py-4 bg-dash-ink text-dash-bg font-mono font-bold uppercase tracking-widest hover:translate-x-[-2px] hover:translate-y-[-2px] hover:shadow-[4px_4px_0px_0px_rgba(100,100,100,1)] transition-all flex items-center justify-center gap-2 group"
          >
            <LogIn className="w-5 h-5 transition-transform group-hover:scale-110" />
            Establish Secure Access
          </button>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-dash-bg flex flex-col md:flex-row">
      {/* Sidebar - Filtration */}
      <aside className="w-full md:w-80 border-r border-dash-line p-6 flex flex-col gap-8 bg-white/50 backdrop-blur-sm shrink-0">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-dash-ink" />
          <h1 className="text-xl font-bold tracking-tighter uppercase leading-none">Intelligence<br/><span className="text-neutral-500">Node — 01</span></h1>
        </div>

        <div className="flex flex-col gap-6">
          <div className="space-y-2">
            <label className="col-header flex items-center gap-2"><Globe className="w-3 h-3" /> Area of Operation</label>
            <select 
              value={selectedRegion}
              onChange={(e) => setSelectedRegion(e.target.value)}
              className="w-full p-2 bg-transparent border border-dash-line font-mono text-xs focus:ring-0 focus:outline-none"
            >
              {REGIONS.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>

          <div className="space-y-2">
            <label className="col-header flex items-center gap-2"><Building2 className="w-3 h-3" /> Target Vertical</label>
            <select 
              value={selectedVertical}
              onChange={(e) => setSelectedVertical(e.target.value)}
              className="w-full p-2 bg-transparent border border-dash-line font-mono text-xs focus:ring-0 focus:outline-none"
            >
              <option value="All">All Sectors</option>
              {VERTICALS.map(v => <option key={v} value={v}>{v}</option>)}
            </select>
          </div>

          <div className="space-y-2">
            <label className="col-header flex items-center gap-2"><Terminal className="w-3 h-3" /> Domain Signature</label>
            <div className="relative">
              <Search className="w-3 h-3 absolute left-3 top-1/2 -translate-y-1/2 opacity-50" />
              <input 
                type="text" 
                placeholder="domain.com"
                value={domainFilter}
                onChange={(e) => setDomainFilter(e.target.value)}
                className="w-full p-2 pl-8 bg-transparent border border-dash-line font-mono text-xs focus:ring-0 focus:outline-none"
              />
            </div>
          </div>

          <button 
            disabled={searching}
            onClick={handleSearch}
            className="w-full py-3 bg-dash-ink text-dash-bg font-mono font-bold uppercase text-[10px] tracking-[0.2em] hover:opacity-90 disabled:opacity-50 transition-opacity flex items-center justify-center gap-2"
          >
            {searching ? <div className="w-3 h-3 border-2 border-dash-bg border-t-transparent animate-spin rounded-full" /> : <Search className="w-3 h-3" />}
            Sync Sources
          </button>
          
          <button 
             onClick={() => setCreatingAlert(!creatingAlert)}
             className={cn("w-full py-3 font-mono font-bold uppercase text-[10px] tracking-[0.2em] border border-dash-ink flex items-center justify-center gap-2", creatingAlert ? "bg-dash-ink text-dash-bg" : "bg-transparent text-dash-ink")}
          >
            <Bell className="w-3 h-3" />
            {creatingAlert ? 'Cancel Alert' : 'Create Custom Alert'}
          </button>

          {/* Sources Management */}
          <div className="pt-6 border-t border-dash-line">
            <label className="col-header block mb-2">Monitor Sources</label>
            <div className="space-y-2 mb-4">
                {sources.map(s => (
                    <div key={s.id} className="flex justify-between items-center bg-white/50 p-2 text-[10px]">
                        <span className="truncate">{s.name}</span>
                        <button onClick={() => deleteSource(s.id)} className="text-red-500">Delete</button>
                    </div>
                ))}
            </div>
            <div className="space-y-2">
                <input placeholder="Name" value={newSourceName} onChange={(e) => setNewSourceName(e.target.value)} className="w-full p-2 bg-transparent border border-dash-line text-xs" />
                <input placeholder="URL" value={newSourceUrl} onChange={(e) => setNewSourceUrl(e.target.value)} className="w-full p-2 bg-transparent border border-dash-line text-xs" />
                <button onClick={addSource} className="w-full py-2 bg-dash-ink text-dash-bg text-[10px] font-bold uppercase">Add Source</button>
            </div>
          </div>

          {creatingAlert && (
            <div className="p-4 border border-dash-line bg-white/50 space-y-4">
               <select value={alertRegion} onChange={(e) => setAlertRegion(e.target.value)} className="w-full p-2 bg-transparent border border-dash-line text-xs">{REGIONS.map(r => <option key={r} value={r}>{r}</option>)}</select>
               <select value={alertVertical} onChange={(e) => setAlertVertical(e.target.value)} className="w-full p-2 bg-transparent border border-dash-line text-xs">{VERTICALS.map(v => <option key={v} value={v}>{v}</option>)}</select>
               <input type="text" placeholder="Keywords (comma separated)" value={alertKeywords} onChange={(e) => setAlertKeywords(e.target.value)} className="w-full p-2 bg-transparent border border-dash-line text-xs" />
               <button onClick={handleCreateAlert} className="w-full py-2 bg-dash-ink text-dash-bg text-[10px] font-bold uppercase">Save Alert</button>
            </div>
          )}
        </div>

        <div className="mt-auto pt-6 border-t border-dash-line/20">
          <div className="flex items-center gap-3 p-3 bg-white/50 border border-dash-line/10 rounded-lg">
            <div className="w-8 h-8 rounded-full bg-dash-ink flex items-center justify-center">
              <User className="w-4 h-4 text-dash-bg" />
            </div>
            <div className="flex-1 overflow-hidden">
              <p className="text-[10px] font-bold truncate uppercase">{user.displayName || user.email}</p>
              <p className="text-[9px] text-neutral-500 uppercase tracking-tighter">Level 07 Agent</p>
            </div>
            <button onClick={() => auth.signOut()} className="opacity-50 hover:opacity-100 transition-opacity">
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Header - Global Stats & Search Bar */}
        <header className="border-b border-dash-line p-6 flex flex-col gap-6 bg-white/20">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div className="flex gap-12">
              <div>
                <p className="col-header">Live Threats</p>
                <p className="text-3xl font-bold tracking-tighter">{threats.length}</p>
              </div>
              <div>
                <p className="col-header">Region Active</p>
                <p className="text-3xl font-bold tracking-tighter">{selectedRegion === 'Global' ? 'Multisync' : selectedRegion.split(' ')[0]}</p>
              </div>
              <div>
                <p className="col-header">System Health</p>
                <div className="flex items-center gap-1 text-3xl font-bold tracking-tighter text-green-600">
                  <CheckCircle2 className="w-5 h-5" /> 99.8%
                </div>
              </div>
            </div>

            <div className="flex-1 max-w-xl relative group">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 opacity-30 group-focus-within:opacity-100 group-focus-within:text-dash-ink transition-all" />
              <input 
                type="text" 
                placeholder="Search actor, technique, or vulnerability..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                className="w-full py-4 pl-12 pr-4 bg-white border border-dash-line/20 rounded-xl focus:ring-0 focus:outline-none focus:border-dash-ink transition-all shadow-sm group-focus-within:shadow-md"
              />
            </div>

            <div className="flex items-center gap-4">
              <button className="relative p-3 bg-white border border-dash-line/10 rounded-full hover:bg-neutral-50 transition-colors">
                <Bell className="w-5 h-5" />
                {notifications.length > 0 && (
                  <span className="absolute top-0 right-0 w-3 h-3 bg-red-600 rounded-full border-2 border-dash-bg animate-bounce" />
                )}
              </button>
            </div>
          </div>
        </header>

        {/* Dashboard Grid */}
        <div className="flex-1 overflow-y-auto p-6 grid grid-cols-1 xl:grid-cols-3 gap-6">
          {/* Main List */}
          <section className="xl:col-span-2 flex flex-col gap-4 min-w-0">
            <div className="flex items-center justify-between">
              <h2 className="col-header flex items-center gap-2"><Terminal className="w-4 h-4" /> Live Intelligence Feed</h2>
              <div className="flex gap-2">
                <span className="px-2 py-0.5 bg-dash-ink text-dash-bg text-[10px] font-bold uppercase rounded">Real-time</span>
              </div>
            </div>

            <div className="space-y-0.5 bg-dash-line/10">
              {filteredThreats.length > 0 ? (
                filteredThreats.map((threat, idx) => (
                  <motion.div 
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    key={threat.id}
                    onClick={() => setSelectedThreat(threat)}
                    className={cn(
                      "data-row",
                      selectedThreat?.id === threat.id && "bg-dash-ink text-dash-bg"
                    )}
                  >
                    <div className="flex items-center justify-center">
                      <div className={cn("w-3 h-3 rounded-full flex items-center justify-center", SEVERITY_COLORS[threat.severity as Severity])}>
                        {threat.severity === 'critical' && <Shield className="w-2 h-2 text-white" />}
                      </div>
                    </div>
                    <div className="flex flex-col min-w-0 pr-4">
                      <p className="font-bold truncate text-sm uppercase tracking-tight">{threat.title}</p>
                      <p className={cn("text-[10px] opacity-60 truncate", selectedThreat?.id === threat.id ? "text-dash-bg" : "text-neutral-500")}>
                        {threat.summary}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Building2 className="w-3 h-3 opacity-30" />
                      <span className="data-value uppercase text-[11px] truncate">{threat.vertical}</span>
                    </div>
                    <div className="flex items-center justify-between gap-4">
                      
                      <button 
                        onClick={(e) => { e.stopPropagation(); handleGenerateIoCs(threat); }}
                        className="p-1.5 hover:bg-white/20 rounded transition-colors"
                        title="Generate IoCs with AI"
                      >
                         <Terminal className="w-3 h-3" />
                      </button>
                      <div className="flex items-center gap-2">
                        <Globe className="w-3 h-3 opacity-30" />
                        <span className="data-value text-[11px]">{threat.region}</span>
                      </div>
                      <ChevronRight className="w-4 h-4 opacity-10" />
                    </div>
                  </motion.div>
                ))
              ) : (
                <div className="p-12 text-center border-2 border-dashed border-dash-line/20 rounded-xl bg-white/30">
                  <AlertCircle className="w-12 h-12 mx-auto mb-4 opacity-20" />
                  <p className="font-mono text-sm uppercase opacity-40">No intelligence matches current filter</p>
                </div>
              )}
            </div>
          </section>

          {/* Side Panels - Trends & Detail */}
          <aside className="flex flex-col gap-6">
            <AnimatePresence mode="wait">
              {selectedThreat ? (
                <motion.div 
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="hardware-card flex flex-col gap-6 overflow-hidden"
                  key="detail-view"
                >
                  <div className="flex items-center justify-between border-b border-white/10 pb-4">
                    <h3 className="font-mono text-xs uppercase tracking-[0.2em] text-cyan-400">Threat Detail__{selectedThreat.severity}</h3>
                    <button onClick={() => setSelectedThreat(null)} className="text-white/40 hover:text-white">
                      <ChevronRight className="w-5 h-5 rotate-180" />
                    </button>
                  </div>

                  <div className="space-y-4">
                    <h2 className="text-2xl font-bold tracking-tighter leading-tight">{selectedThreat.title}</h2>
                    <div className="flex flex-wrap gap-2">
                      {(selectedThreat.keywords || []).map(kw => (
                        <span key={kw} className="px-2 py-0.5 bg-white/10 rounded font-mono text-[9px] uppercase tracking-wider">{kw}</span>
                      ))}
                    </div>
                  </div>

                  <div className="p-4 bg-black/40 rounded-lg border border-white/5 space-y-4">
                    <p className="text-xs text-white/70 leading-relaxed font-mono">
                      {selectedThreat.summary}
                    </p>
                    {selectedThreat.sourceUrl && (
                      <a 
                        href={selectedThreat.sourceUrl} 
                        target="_blank" 
                        rel="noreferrer"
                        className="flex items-center gap-2 text-[10px] font-bold text-cyan-400 uppercase tracking-widest hover:underline"
                      >
                        Source Evidence <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>

                  {(selectedThreat.actors || []).length > 0 && (
                    <div className="space-y-2">
                      <p className="col-header text-white/50">Identified Actors</p>
                      <div className="flex flex-wrap gap-2">
                        {selectedThreat.actors.map(actor => (
                          <button 
                            key={actor}
                            onClick={() => handleViewActor(actor)}
                            className="flex items-center gap-2 px-3 py-1.5 bg-white/5 border border-white/10 rounded-md hover:bg-white/10 transition-colors group"
                          >
                            <span className="font-mono text-[11px]">{actor}</span>
                            <MousePointer2 className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                          </button>
                        ))}
                      </div>
                    </div>
                  )}

                  {(selectedThreat.iocs || []).length > 0 && (
                    <div className="space-y-3 pt-4 border-t border-white/10">
                      <div className="flex items-center justify-between">
                        <p className="col-header text-white/50">Indicators of Compromise</p>
                        <button 
                          onClick={() => downloadIoCs(selectedThreat)}
                          className="text-[10px] flex items-center gap-1 font-bold text-cyan-400 hover:text-cyan-300"
                        >
                          <Download className="w-3 h-3" /> EXPORT CSV
                        </button>
                      </div>
                      <div className="max-h-32 overflow-y-auto space-y-1 pr-2 custom-scrollbar">
                        {selectedThreat.iocs.map((ioc, i) => (
                          <div key={i} className="flex items-center justify-between py-1 border-b border-white/5">
                            <span className="font-mono text-[10px] text-zinc-500 uppercase">{ioc.type}</span>
                            <span className="font-mono text-[10px] text-white truncate max-w-[150px]">{ioc.value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </motion.div>
              ) : (
                <motion.div 
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex flex-col gap-6"
                  key="stats-view"
                >
                  {/* Trends Chart */}
                  <div className="bg-white border border-dash-line p-6 rounded-xl space-y-4 h-[300px]">
                    <h3 className="col-header flex items-center gap-2"><BarChart3 className="w-4 h-4" /> Vertical Distribution</h3>
                    <div className="h-[200px] w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={trendsData}>
                          <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#E5E5E5" />
                          <XAxis dataKey="name" hide />
                          <YAxis hide />
                          <Tooltip 
                            contentStyle={{ backgroundColor: '#141414', border: 'none', borderRadius: '8px' }}
                            itemStyle={{ color: '#E4E3E0', fontSize: '10px', textTransform: 'uppercase' }}
                            labelStyle={{ color: '#888', fontSize: '9px', marginBottom: '4px' }}
                          />
                          <Bar dataKey="value" fill="#141414" radius={[4, 4, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="flex flex-wrap gap-x-4 gap-y-1">
                      {trendsData.map((d, i) => (
                        <div key={i} className="flex items-center gap-1.5 font-mono text-[9px] uppercase">
                          <div className="w-1.5 h-1.5 rounded-full bg-dash-ink" />
                          <span className="opacity-40">{d.name}</span>
                          <span className="font-bold">{d.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Active Notifications */}
                  <div className="bg-white border border-dash-line p-6 rounded-xl space-y-4 max-h-[400px] overflow-hidden flex flex-col">
                    <h3 className="col-header flex items-center gap-2"><Bell className="w-4 h-4" /> Operations Registry</h3>
                    <div className="flex-1 overflow-y-auto space-y-3 pr-2 scrollbar-hide">
                      {notifications.length > 0 || alerts.length > 0 ? (
                        <>
                          {notifications.map((note, i) => (
                            <div key={`note-${i}`} className="flex gap-3 text-[11px] leading-tight bg-white p-2 rounded items-center border border-sky-100">
                              <AlertCircle className="w-3 h-3 text-sky-600" />
                              <p className="font-medium text-sky-900">{note}</p>
                            </div>
                          ))}
                          {alerts.map(alert => (
                            <div key={alert.id} className="flex gap-3 text-[11px] leading-tight text-blue-900 bg-blue-50 p-2 rounded border border-blue-100">
                              <Bell className="w-3 h-3 mt-0.5 text-blue-600" />
                              <p className="font-medium">Alert: {alert.filters.region} / {alert.filters.vertical}</p>
                            </div>
                          ))}
                        </>
                      ) : (
                        <p className="text-center font-mono text-[10px] opacity-30 italic py-12">Registry clear. Monitoring system live.</p>
                      )}
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </aside>
        </div>
      </main>

      {/* Actor Profile Modal */}
      <AnimatePresence>
        {actorProfile && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-6 bg-dash-ink/80 backdrop-blur-sm">
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="max-w-2xl w-full hardware-card"
            >
              <div className="flex items-center justify-between border-b border-white/10 pb-4 mb-6">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-red-600 rounded-lg">
                    <AlertTriangle className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold uppercase tracking-tighter">Actor_Profile</h2>
                    <p className="font-mono text-[10px] uppercase text-red-500 tracking-widest">Classification: Classified / Restricted</p>
                  </div>
                </div>
                <button onClick={() => setActorProfile(null)} className="p-2 hover:bg-white/10 rounded-full transition-colors">
                  <ChevronRight className="w-6 h-6 rotate-180" />
                </button>
              </div>

              <div className="space-y-6">
                <div>
                  <h3 className="text-4xl font-bold tracking-tighter uppercase mb-2">{actorProfile.name}</h3>
                  <div className="h-1 w-24 bg-red-600" />
                </div>

                <div className="p-6 bg-black/40 rounded-xl border border-white/5 space-y-4">
                  <h4 className="col-header text-white/50">Threat Assessment</h4>
                  <p className="text-sm leading-relaxed text-white/80 font-mono">
                    {actorProfile.description}
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-3">
                    <h4 className="col-header text-white/50">TTP Persistence</h4>
                    <div className="space-y-2">
                      {(actorProfile.techniques || []).map((t, i) => (
                        <div key={i} className="flex items-center gap-3 font-mono text-[11px] p-2 bg-white/5 border border-white/5 rounded">
                          <div className="w-1.5 h-1.5 rotate-45 bg-cyan-400" />
                          {t}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-3 p-4 border border-white/10 rounded-xl bg-white/5">
                    <h4 className="col-header text-white/50">Metadata</h4>
                    <div className="space-y-4">
                      <div>
                        <p className="text-[9px] text-white/40 uppercase mb-1">Status</p>
                        <p className="font-mono text-xs text-green-500">ACTIVE_MONITORING</p>
                      </div>
                      <div>
                        <p className="text-[9px] text-white/40 uppercase mb-1">Last Node Sync</p>
                        <p className="font-mono text-xs">{formatDate(actorProfile.lastSeen)}</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-8 pt-6 border-t border-white/10 flex justify-end">
                <button 
                  onClick={() => setActorProfile(null)}
                  className="px-8 py-3 bg-white text-dash-ink font-mono font-bold uppercase text-[11px] tracking-widest hover:bg-white/90 transition-colors"
                >
                  Close Archive
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
