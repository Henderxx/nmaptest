'use strict'
const libnmap = require('libnmap')
const fs = require('fs')
const path = './scans/'
const chalk = require('chalk')

const opts = {
    ports: '9000',
    range: ['192.168.0.20-250',],
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
         '-T5', // Scan Type from in range 0-5, 0 slowest 5 fastest
         '--max-retries 4', // Don't give up on slow responding hosts
        // '--data-string hello', // Custom data to send as probe packet
        // '--ttl 200ms', // Accomodate for slow connections by setting the packets TTL value higher
        // '--scan-delay 10s', // Account for host 'rate limiting'
        // '--max-rate 30', // Slows down packet spewing to account for IDS protections
    ]
}
let foundHosts = {}

const date = new Date()
const year = date.getFullYear()
const month = date.getMonth() +1
const day = date.getDate()
const HH = date.getHours()
const MM = date.getMinutes()
const SS = date.getSeconds()
const filename = `${year}_${month}_${day}_${HH}-${MM}-${SS}`

libnmap.scan(opts, function(err, report) {
    if (err) throw new Error(err)
    
    for (let item in report) {
      let data = JSON.stringify(report[item], null, 2)

      if(report[item].host && report[item].host.length <= 1){
      const ipaddr = report[item].host[0].address[0].item.addr
      const macaddr = report[item].host[0].address[1].item.addr
      const portState = report[item].host[0].ports[0].port[0].state[0].item.state
      const portStateReason = report[item].host[0].ports[0].port[0].state[0].item.reason
      const resultObj = {'mac': macaddr,'port_state': portState,'state_reason': portStateReason}

      foundHosts[ipaddr] = resultObj

      saveReport(foundHosts)

      } else {
        if (!report[item].host) return console.log(chalk.red(`No items found`))
        const hosts = report[item].host
        const FilteredHosts = hosts.filter(host => host.ports[0].port[0].state[0].item.state.includes('open') )
        if (!FilteredHosts.length) return console.log(chalk.red(`No items found`))
        FilteredHosts.forEach(element => {
          const ipaddr = element.address[0].item.addr
          const macaddr = element.address[1].item.addr
          const portState = element.ports[0].port[0].state[0].item.state
          const portStateReason = element.ports[0].port[0].state[0].item.reason
          const resultObj = {'mac': macaddr,'port_state': portState,'state_reason': portStateReason}
         foundHosts[ipaddr] =  resultObj
          
        });
        saveReport(foundHosts)
      }

      //console.log(foundHosts)
    }
  })

  function saveReport(data) {
    const dataToWrite = JSON.stringify(data, null, 2)
    fs.writeFile(path+filename+'.json',dataToWrite, function(error) {
      if (error) return console.log(error)

      console.log(`Wrote report for ${filename}`)
      foundHosts = {}
      })
  }