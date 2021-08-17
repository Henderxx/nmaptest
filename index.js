const libnmap = require('libnmap');

const options = {
    ports: '6564',
    range: ['192.168.0.0/23'],
    threshold: 2048, // maximum of 2048 child processes (depending on range & blocksize)
    timeout: 900, // 900s = 15m and increases the reliability of scan results
    udp: true, // requires root privileges
    // json: false, //report in xml
    flags: [
        '-sV' // Open port to determine service (i.e. FTP, SSH etc)
        // '-O', // OS finger printing (requires elevated privileges)
        // '-sC', // Enables the nmap scripts (all) against each host (requires elevated privileges)
        // '--traceroute', // Turns on tracerouting
        // '--script traceroute-geolocation' // Turns on GeoIP functionality per hops
        // '-T0', // Paranoid scan type; very slow but accurate
        // '--max-retries 10', // Don't give up on slow responding hosts
        // '--ttl 200ms', // Accomodate for slow connections by setting the packets TTL value higher
        // '--scan-delay 10s', // Account for host 'rate limiting'
        // '--max-rate 30', // Slows down packet spewing to account for IDS protections
    ]
}

libnmap.scan(options, (err,report) => {
    if (err) throw new Error(err)

    for( const item in report){
        //const wynikskanu = JSON.stringify(repot[item], null, 2)
        
        console.log(JSON.stringify(repot[item], null, 2));
    }
})