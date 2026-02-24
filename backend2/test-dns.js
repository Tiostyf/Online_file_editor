// test-dns.mjs
import dns from 'dns';

// Optional: force Google DNS
dns.setServers(['8.8.8.8', '8.8.4.4']);

dns.resolveSrv('_mongodb._tcp.rudra.ohcboym.mongodb.net', (err, addresses) => {
    if (err) {
        console.error('❌ SRV lookup failed:', err);
    } else {
        console.log('✅ SRV records:', addresses);
    }
});