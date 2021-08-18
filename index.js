'use strict'
const libnmap = require('libnmap');
const fs = require('fs');
const path = './scans/'

const opts = {
    ports: '9000',
    range: ['192.168.0.26','192.168.0.250'],
    threshold: 2048, // maximum of 2048 child processes (depending on range & blocksize)
    timeout: 900, // 900s = 15m and increases the reliability of scan results
    udp: true, // requires root privileges
    // json: false, //report in xml
    flags: [
        //'-sV' // Open port to determine service (i.e. FTP, SSH etc)
        // '-O', // OS finger printing (requires elevated privileges)
        // '-sC', // Enables the nmap scripts (all) against each host (requires elevated privileges)
        // '--traceroute', // Turns on tracerouting
        // '--script traceroute-geolocation' // Turns on GeoIP functionality per hops
         '-T5', // Paranoid scan type; very slow but accurate
         '--max-retries 4', // Don't give up on slow responding hosts
        // '--ttl 200ms', // Accomodate for slow connections by setting the packets TTL value higher
        // '--scan-delay 10s', // Account for host 'rate limiting'
        // '--max-rate 30', // Slows down packet spewing to account for IDS protections
    ]
}

libnmap.scan(opts, function(err, report) {
    if (err) throw new Error(err);
    const date = new Date()
    const year = date.getFullYear()
    const month = date.getMonth() +1
    const day = date.getDate()
    const HH = date.getHours()
    const MM = date.getMinutes()
    const SS = date.getSeconds()
    const filename = `${year}_${month}_${day}_${HH}-${MM}-${SS}`
const ilosc_urzadzen = Object.keys(report)
    
    for (let item in report) {
      //console.log(JSON.stringify(report[item]), null, 2)
      let data = JSON.stringify(report[item], null, 2)//, filename = item.replace(' ', '-')
      //const key = Object.keys(report[item].host[0].address[0].item.addr)
      //const val = Object.values(report[item].host[0].address[0].item.addr)
      if(report[item].host){
      const ipaddr = report[item].host[0].address[0].item.addr
      const macaddr = report[item].host[0].address[1].item.addr
      const findport = report[item].host[0].ports[0].port[0].state[0].item.state
      //console.log(item.host)
      

      fs.writeFile(path+filename+ipaddr+'.txt', `${ipaddr}:${macaddr}__${findport}`, function(error) {
        if (error) return console.log(error);
  
        console.log('Wrote report for '+filename);
        })
      }
    }
  })