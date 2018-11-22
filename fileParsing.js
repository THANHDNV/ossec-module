#!/usr/bin/env node

const chokidar = require('chokidar');
const path = require('path');
const util = require('util');
const fs = require('fs');
const mongoose = require('mongoose');
const uname = require('node-uname')
const child_process = require('child_process')
const moment = require('moment')
const mongooseAutoIncrementID = require('mongoose-auto-increment-reworked').MongooseAutoIncrementID

var url =  "mongodb://127.0.0.1:27017";
var globalDb = "global";
var agentCollection = "%s_%s";
var childObj = {}

var ossecDir = "/var/ossec";
const rootcheckDir = ossecDir + "/queue/rootcheck"
const syscheckDir = ossecDir + "/queue/syscheck"
const filesAndDir = [ossecDir + "/etc/client.keys", ossecDir + "/queue/agent-info/", rootcheckDir, syscheckDir];

//init mongoose schema and model
mongoose.Promise = global.Promise;
const Schema = mongoose.Schema;
var agentInfoSchema = Schema({
  id: String,
  name: String,
  ip: String,
  key: String,
  dateAdd: {type: Date, default: Date.now},
  os: String,
  os_arch: String,
  version: String,
  config_sum: String,
  lastAlive: Date
});
agentInfoSchema.index({"id": 1});
const agentInfoModel = mongoose.model("agent", agentInfoSchema, "agent");

const agentRootcheckSchema = Schema({
  date_first: Date,
  date_last: Date,
  log: String,
  pci_dss: Boolean 
})
const agentRootcheckModel = mongoose.model("rootcheck", agentRootcheckSchema, "pm_event")

const syscheckFileSchema = Schema({
  path: String,
  type: String
})
var syscheckFilePlugin = new mongooseAutoIncrementID(syscheckFileSchema, 'syscheck-file')
syscheckFilePlugin.applyPlugin()
const syscheckFileModel = mongoose.model('syscheck-file', syscheckFileSchema, "fim_file")

const syscheckEventSchema = Schema({
  id_file: Object,
  type: String,
  date: Date,
  size: Number,
  perm: Number,
  uid: Number,
  gid: Number,
  md5: String,
  sha1: String
})
var syscheckEventPlugin = new mongooseAutoIncrementID(syscheckEventSchema, 'syscheck')
syscheckEventPlugin.applyPlugin()
const syscheckEventModel = mongoose.model('syscheck', syscheckEventSchema, 'fim_event')
//agent CRUD
async function updateAgentBasicInfo(fPath = ossecDir + "/etc/client.keys") {
  mongoose.connect(url + "/" + globalDb);
  var db = mongoose.connection;
  db.on('error', err => console.log("Connection Error: " + err));
  db.on('open', () => {
    var data = "";

    // console.log(fPath)
    try {
      data = fs.readFileSync(fPath, 'utf8');
      var lines = data.trim().split("\n");
      // console.log(lines);
      if (lines.length > 0) {
        agentInfoModel.find().then(res => {
          //Newly added or modified agents
          var aAgentList = lines.filter(line => {
            var id = line.toString().split(" ")[0];
              var name = line.toString().split(" ")[1];
            var found = res.find(agent => {
              return agent.id == id && agent.name == name
            })
            return (typeof found === 'undefined')
          })

          //Deleted agent
          var dAgentList = res.filter(agent => {
            var found = lines.find(line => {
              var id = line.toString().split(" ")[0];
              var name = line.toString().split(" ")[1];
              return agent.id == id && agent.name == name && agent.id != "000"
            })
            return (typeof found === 'undefined')
          })

          //modify agent info
          //add or update
          async function updateInfo(line) {
            var agentInfoArray = line.toString().split(' ');
            var agentObj = {
              $set: {
                name: agentInfoArray[1],
                ip: agentInfoArray[2],
                key: agentInfoArray[3]
              },
              $setOnInsert: {
                id: agentInfoArray[0]
              }
            }
            agentInfoModel.findOneAndUpdate({
              id: agentInfoArray[0]
            }, agentObj, {
              new: true,
              upsert: true,
              setDefaultsOnInsert: true
            }, (err, doc, res) => {
              if (err) {
                console.log("Update Error : " + err)
              } else {
                // console.log(doc)
              }
            })      
          }

          async function asyncForEach(array, callback) {
            for (let index = 0; index < array.length; index++) {
              await callback(array[index])
            }
          }

          asyncForEach(aAgentList, updateInfo);

          //delete

          async function deleteInfo(agent) {
            agentInfoModel.findOneAndDelete({
              id: agent.id
            }, (err, res) => {
              if (err) {
                console.log("Delete Error: " + err)
              } else {
                // console.log(res);
              }
            })
          }

          asyncForEach(dAgentList, deleteInfo);

          db.close();
        }, err => {
          console.log("Get agent info error: " + err);
        })
      } else {
        //All agents are deleted
        agentInfoModel.findOneAndDelete({}, (err, res) => {
          if (err) {
            console.log("Delete all error: " + err)
          } else {
            // console.log(res)
          }
        }).then(() => {
          db.close(); 
        })
      }
    } catch (error) {
      console.log("Read file error: " + error);
    }
  })
}

async function initManagerInfo(ossec_path= ossecDir) {
  return new Promise((res,rej) => {
    mongoose.connect(url + "/" + globalDb);
    var db = mongoose.connection;
    db.on('error', err => console.log("Connection Error: " + err));
    db.on('open', () => {
      var conf_file_path = path.join(ossec_path, "etc/ossec-init.conf")
      var data = "";
      try {
        data = fs.readFileSync(conf_file_path, 'utf8').trim();
        var dataArr = data.split("\n");
        var version = ""
        for (line in dataArr) {
          var lineArr = dataArr[line].split('=');
          lineArr.push("")
          property = lineArr[0];
          value = lineArr[1];
          if (property.toLowerCase() == 'version') {
            version = value.substring(1,value.length - 1)
          }
        }
        var info = uname.uname();
        var managerObj = {
          $set: {
            name: info.nodename,
            version: "OSSEC HIDS " + version,
            os: info.sysname + " " + info.nodename + " " + info.release + " " + info.version + " " + info.machine,
            os_arch: info.machine
          },
          $setOnInsert: {
            id: "000",
            ip: "127.0.0.1"
          }
        }

        agentInfoModel.findOneAndUpdate({
          id: "000"
        }, managerObj, {
          new: true,
          upsert: true
        }, (err, doc, res) => {
          if (err) {
            console.log("Add manager error: " + err)
          } else {
            // console.log(doc)
          }
        }).then(() => {
          db.close();
          res();
        })
      } catch (error) {
        console.log("Config File reading error: " + error)
        rej();
      }
    })
  })
}

async function updateAgentInfoFromFile(filePath) {
  function getOsArch(os) {
    var archs = [ "x86_64", "i386", "i686", "sparc", "amd64", "ia64", "AIX", "armv6", "armv7", "" ]
    for (i = 0; i < archs.length; i++) {
      if (os.indexOf(archs[i]) > -1) {
        return archs[i];
      }
    }
  }
  try {
    var data = fs.readFileSync(filePath, 'utf8').trim();
    var filename = path.basename(filePath)
    var name = filename.split("-")[0];
    var ip = filename.split("-")[1];

    var os_arch = getOsArch(data)
    var mTime = fs.statSync(filePath).mtime;
    var dataArr = data.split(" - ")
    var ossecVersionArr = dataArr[1].split(" / ");
    ossecVersionArr.push("")
    var version = ossecVersionArr[0];
    var configSum = ossecVersionArr[1];

    //create update info obj
    var agentUpdateInfo = {
      $set: {
        os: dataArr[0],
        os_arch: os_arch,
        lastAlive: mTime,
        version: version,
        config_sum: configSum,
      },
      $setOnInsert: {
        name: name,
        ip: ip
      }
    }

    //connect to mongodb
    mongoose.connect(url + "/" + globalDb);
    var db = mongoose.connection;
    db.on('err', err => Console.log("Connection Error: " + err))
    db.on("open", () => {
      agentInfoModel.findOneAndUpdate({
        name: name,
        ip: ip,
      }, agentUpdateInfo, {
        new: true,
        upsert: false
      }, (err, doc, res) => {
        if (err) {
          console.log("Update Error: " + err);
        } else {
          // console.log(doc)
          // console.log(res)
          console.log("Updated");
        }
      }).then(() => {
        db.close();
      })
    })
  } catch (error) {
    console.log("File Readind Error: " + error);
  }
  
}

// read files synchronously and get agent info
async function readFilesFirst() {
  await initManagerInfo();
  filesAndDir.forEach((fPath, index) => {
    var isFile = false;;
    try {
      isFile = fs.statSync(fPath).isFile();
    } catch (error) {
      return;
    }
    if (isFile) {
      // client.keys
      updateAgentBasicInfo(fPath);
    } else {
      //other folders
      if (fPath.indexOf("/queue/agent-info") > -1) {
        //read each files in agent-info
        try {
          var fileNames = fs.readdirSync(fPath, "utf8");

          fileNames.forEach((filename, index) => {
            fileNames[index] = path.join(fPath, filename);
          })

          async function asyncForEach(array, callback) {
            for (let index = 0; index < array.length; index++) {
              await callback(array[index])
            }
          }

          asyncForEach(fileNames, updateAgentInfoFromFile);
        } catch (error) {
          console.log(error);
        }
      } else if (fPath.indexOf("/queue/rootcheck/") > -1) {
        readRootcheck()
      } else if (fPath.indexOf("/queue/syscheck/") > -1) {
        readSyscheck()
      }
    }
  })
}

//read rootcheck
async function readRootcheck() {
  fs.exists(rootcheckDir, (exists) => {
    if (exists) {

      fs.readdir(rootcheckDir, (err, filenames) => {
        if (err) {
          console.log("Read Rootcheck dir Error: " + err)
        } else {
          filenames.forEach(filename => {
            filename = path.join(rootcheckDir, filename)
            if (!fs.statSync(filename).isFile()) return
            var agentDb = ""
            if (matchArr = filename.match(/\(([^)]+)\)\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\-\>rootcheck$/)) {
              var name = matchArr[1]
              var ip = matchArr[2]

              //read client.keys to get agent id
              var agentId = -1

              try {
                var clientsData = fs.readFileSync(ossecDir + "/etc/client.keys", 'utf8').trim();
                var clientsArr = clientsData.split("\n")
                var regex = new RegExp(name + ' ' + ip)
                for (index in clientsArr) {
                  var line = clientsArr[index]
                  if (line.search(regex) > -1) {
                    var lineArr = line.split(" ")
                    agentId = lineArr[0]
                    break;
                  }
                }

                agentDb = agentId + "-" + name
              } catch (error) {
                console.log("Read client.keys file error: " + error)
              }
            } else if (matchArr = filename.match(/^rootcheck$/)){
              agentDb = "000"
            } else {
              return
            }

            var child = child_process.spawn("tail", ["-f",'-n','+1', filename])
            var chunkLeftover = [""]
            child.stdout.on('data', logDataChunk => {
              child.stdout.pause()
              //need to process chunk before becoming logData
              logDataChunk = chunkLeftover.shift().concat(logDataChunk.toString())
              if (logDataChunk[logDataChunk.length - 1] != '\n') {
                  if ((index = logDataChunk.lastIndexOf('\n')) > -1) {
                      chunkLeftover.push(logDataChunk.substring(index + 1))
                      logDataChunk = logDataChunk.substring(0,index + 1)
                  } else {
                      chunkLeftover.push(logDataChunk)
                      logDataChunk = ""
                  }
              }
              var logData = logDataChunk.toString().trim().split("\n")

              //process logData
              var pm_event_arr = []
              
              for (index in logData) {
                var line = logData[index].trim()
                if (line.length > 0) {
                  var start_time_E = line.substr(1,10)
                  var start_time = moment.unix(start_time_E).toDate()
                  var end_time_E = line.substr(12, 10)
                  var end_time = moment.unix(end_time_E).toDate()
                  var log = line.substr(23)
                  regex = new RegExp(/\{PCI_DSS\: ([^\}]+)\}/)
                  var pci_dss = log.match(regex) ? log.match(regex)[1] : null

                  var event = {
                    start_time: start_time,
                    end_time: end_time,
                    log: log,
                    pci_dss: pci_dss
                  }

                  pm_event_arr.push(event)
                }
              }

              mongoose.connect(url + "/" + agentDb)
              var db = mongoose.connection
              db.on('error', err => console.log("Connection Error: " + err));
              db.on('open', () => {
                agentRootcheckModel.insertMany(pm_event_arr, (err, doc) => {
                  if (err) {
                    console.log("Insert event error: " + err)
                  } else {
                    // console.log(doc)
                  }
                }).then(() => { db.close() })
              })
            })

            childObj[filename] = child
            child.stdout.resume()
          })
        }
      })

    } else {
      console.log("Rootcheck folder not exist")
    }
  })
}

//read syscheck
async function readSyscheck() {
  fs.exists(syscheckDir, exists => {
    if (exists) {
      
      fs.readdir(syscheckDir, (err, filenames) => {
        if (err) {
          console.log("Read Rootcheck dir Error: " + err)
        } else {
          filenames.forEach(filename => {
            filename = path.join(syscheck, filename)
            if (!fs.statSync(filename).isFile()) return
            var agentDb = ""
            if (matchArr = filename.match(/\(?([^)]+)\)?\s?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?\-\>(syscheck|syscheck-registry)$/)) {
              var name = matchArr[1]
              var ip = matchArr[2]
              var type = matchArr[3]

              //read client.keys to get agent id
              var agentId = -1

              try {
                var clientsData = fs.readFileSync(ossecDir + "/etc/client.keys", 'utf8').trim();
                var clientsArr = clientsData.split("\n")
                var regex
                if (typeof ip !== 'undefined') {
                  regex = new RegExp(name + ' ' + ip)
                } else {
                  regex = new RegExp(name)
                }
                
                for (index in clientsArr) {
                  var line = clientsArr[index]
                  if (line.search(regex) > -1) {
                    var lineArr = line.split(" ")
                    agentId = lineArr[0]
                    break;
                  }
                }

                agentDb = agentId + "-" + name
              } catch (error) {
                console.log("Read client.keys file error: " + error)
              }
            } else if (matchArr = filename.match(/^syscheck$/)){
              agentDb = "000"
            } else {
              return
            }

            var child = child_process.spawn("tail", ["-f", '-n', '+1', filename])

            child.stdout.on('data', logDataChunk => {
              child.stdout.pause()
              //need to process chunk before becoming logData
              logDataChunk = chunkLeftover.shift().concat(logDataChunk.toString())
              if (logDataChunk[logDataChunk.length - 1] != '\n') {
                  if ((index = logDataChunk.lastIndexOf('\n')) > -1) {
                      chunkLeftover.push(logDataChunk.substring(index + 1))
                      logDataChunk = logDataChunk.substring(0,index + 1)
                  } else {
                      chunkLeftover.push(logDataChunk)
                      logDataChunk = ""
                  }
              }
              var logData = logDataChunk.toString().trim().split("\n")

              mongoose.connect(url + "/" + agentDb).then(() => {
                var db = mongoose.connection
                for (index in logData) {
                
                  var line = logData[index].toString().trim()
                  if (line.length > 0) {
                    // process line data 
                    if (match = line.match(/^(([#\+\!]{3})(\d+):(\d+):(\d+):(\d+):([\w\d]+):([\w\d]+)|(\-1))\s\!(\d{10})\s(.+)$/)) {
                      var eventCode = ""
                      var event = ""
                      var id_file = -1
                      var size = null
                      var perm = null
                      var uid = null
                      var gid = null
                      var md5 = null
                      var sha1 = null
                      var time_E = match[10]
                      var time = moment.unix(time_E).toDate()
                      var filePath = match[11]
                      if (attr = match[1].match(/^([#\+\!]{3})(\d+):(\d+):(\d+):(\d+):([\w\d]+):([\w\d]+)/)) {
                        //not delete event
                        eventCode = attr[1]
                        size = attr[2]
                        perm = atrr[3]
                        uid = attr[4]
                        gid = attr[5]
                        md5 = attr[6]
                        sha1 = attr[7]
                      } else if (attr = match[1].match(/^[\+#!]*\-1/)) {
                        //delete event
                        eventCode = '-1'
                        event = 'deleted'
                      }

                      //look for file
                      syscheckFileModel.findOne({
                        path: filePath,
                        type: type
                      }, (findErr, findRes) => {
                        if (findErr) {
                          console.log("Find Error: " + findErr)
                        } else if (findRes) {
                          // have existed
                          // look for the file events in db
                          id_file = findRes._id
                          syscheckEventModel.find({
                            id_file: id_file
                          }).sort({ _id: -1 }).limit(1).exec((fErr, docs) => {
                            if (docs) {
                              // found last event of the file
                              //suppose to have 1 and only 1 doc
                              if (docs.length == 1) {
                                var doc = docs[0]
                                if (doc.event == "added" || doc.event == 'modified' || doc.event =='readded') {
                                  event = 'modified'
                                } else {
                                  event = 'readded'
                                }
                              }
                            } else {
                              // no event was found - impossible since inserting into pim_file will also insert an event into fim_event
                            }
                          })
                        } else {
                          //file not existed in db
                          if (eventCode[0] == "+" || (eventCode[0] == '#' && eventCode[1] == '+')) {
                            event = "added"
                          } else {
                            event = "modified"
                          }
                          //save new file to fim_file
                          var newFimFile = new syscheckFileModel({
                            path: filePath,
                            type: type
                          })
                          try {
                            var fimFile = newFimFile.save()
                            id_file = fim_file._id
                          } catch (sErr) {
                            console.log('Error saving fim file: ' + sErr)
                          }
                          newFimFile.save()
                        }
                      })
                      var newFimEvent = new syscheckEventModel({
                        id_file: id_file,
                        type: event,
                        date: time,
                        size: size,
                        perm: perm,
                        uid: uid,
                        gid: gid,
                        md5: md5,
                        sha1: sha1
                      })
                      try {
                        var fimEvent = await newFimEvent.save()
                        // console.log(fimEvent)
                      } catch (sErr) {
                        console.log('Error saving fim event: ' + sErr)
                      }
                    }
                  }
                }
              }).then(mongoose.connection.close)
              //continue the stream
              child.stdout.resume()
            })

            childObj[filename] = child
          })
        }
      })

    } else {
      console.log("No syscheck folder")
    }
  })
}

// watcher will watch file asynchronously

async function watchFile(){
  var watcher = chokidar.watch(filesAndDir, {persistent: true});

watcher
  .on('add', function(fPath, stat) {
    //File is added to watcher list
    console.log("File ", fPath, " has been added")
    if (fPath.indexOf("/etc/client.keys") > -1) {

    } else if (fPath.indexOf("/queue/agent-info/") > -1) {
      //Add new agent info
      updateAgentInfoFromFile(fPath);
    }
  })
  .on('change', function(fPath, stat) {
    //File on watcher list changed
    console.log('File', path, 'has been changed');
    if (fPath.indexOf("/etc/client.keys")) {
      updateAgentBasicInfo()      
    }
    else if (fPath.indexOf("/queue/agent-info/") > -1) {
      // agent info modified
      updateAgentInfoFromFile(fPath);    
    }
  })
  .on('unlink', function(fPath) {
    if (fPath.indexOf("/etc/client.keys")) {
      //impossible

    }
    else if (fPath.indexOf("/queue/agent-info/") > -1) {
      // agent info deleted
      var filename = path.basename(fPath);
      var name = filename.split("-")[0];
      var ip = filename.split("-")[1];

      mongoose.connect(url + "/" + globalDb);
      var db = mongoose.connection;
      db.on('error', () => console.log("Connection Error: " + error))
      db.on('open', () => {
        agentInfoModel.findOneAndDelete({
          ip: ip,
          name: name
        }, (err, res) => {
          if (err) {
            console.log("Delete Error: " + err);
          } else {

          }
        }).then(() => {
          db.close();
        })
      })
    } else if (fPath.indexOf("/queue/rootcheck/") > -1) {

    } else if (fPath.indexOf("/queue/syscheck/") > -1) {
      childObj[fPath].kill()
    }
    //file on watcher list deleted
    console.log('File', fPath, 'has been removed');
  })
  .on('error', function(error) {
    //Unhanded error
    console.error('Error happened', error);
  })
}

//calling main
async function main() {
  readFilesFirst().then(watchFile);
}

main();