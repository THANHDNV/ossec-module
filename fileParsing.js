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
const rootcheckDir = ossecDir + "/queue/rootcheck/"
// const rootcheckDir = "rootcheck/"
const syscheckDir = ossecDir + "/queue/syscheck/"
// const syscheckDir = "syscheck/"
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
  pci_dss: String
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
  file_id: Number,
  type: String,
  date: Date,
  size: Number,
  perm: Number,
  uid: String,
  gid: String,
  md5: String,
  sha1: String
})
var syscheckEventPlugin = new mongooseAutoIncrementID(syscheckEventSchema, 'syscheck')
syscheckEventPlugin.applyPlugin()
const syscheckEventModel = mongoose.model('syscheck', syscheckEventSchema, 'fim_event')
//agent CRUD
async function updateAgentBasicInfo(fPath = ossecDir + "/etc/client.keys") {
  return new Promise((resolve, reject) => {
    mongoose.connect(url + "/" + globalDb).then(() => {
      return new Promise((resolve2, reject2) => {
        var db = mongoose.connection;
        var data = "";
        // console.log(fPath)
        try {
          data = fs.readFileSync(fPath, 'utf8');
          var lines = data.trim().split("\n");
          // console.log(lines);
          if (lines.length > 0 && line.match()) {
            agentInfoModel.find().then(res => {
              return new Promise((findResolve, findReject) => {
                //Newly added or modified agents
                var aAgentList = lines.filter(line => {
                  var id = line.toString().split(" ")[0];
                    var name = line.toString().split(" ")[1];
                  var found = res.find(agent => {
                    return agent.id == id && agent.name == name
                  })
                  return (typeof found === 'undefined') && line.match(/\d{3}\s\S+\s\S+\s\S+/)
                })
                // console.log("add agent")
                // console.log(aAgentList)

                //Deleted agent
                var dAgentList = res.filter(agent => {
                  var found = lines.find(line => {
                    var id = line.toString().split(" ")[0];
                    var name = line.toString().split(" ")[1];
                    return agent.id == id && agent.name == name && line.match(/\d{3}\s\S+\s\S+\s\S+/)
                  })
                  return ((typeof found === 'undefined') && agent.id != "000")
                })
                // console.log("delete agent")
                // console.log(dAgentList)

                //modify agent info
                //add or update
                async function updateInfo(line) {
                  return new Promise((resolve3, reject3) => {
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
                    }).exec().then(()=> {
                      resolve3()
                    }).catch(err => {
                      console.log("Update Error : " + err + " - " + moment.now())
                    })
                  })
                }

                async function deleteInfo(agent) {
                  return new Promise((resolve3, reject3) => {
                    console.log()
                    agentInfoModel.findOneAndDelete({
                      id: agent.id
                    }).exec((err, res) => {
                      if (err) {
                        console.log("Delete Error: " + err)
                      } else {
                        // console.log(res);
                        resolve3()
                      }
                    })
                  })
                }

                async function asyncForEach(array, callback) {
                  return new Promise((forResolve, forReject) => {
                    async function main() {
                      for (i=0;i<array.length;i++) {
                        await callback(array[i])
                      }
                      forResolve()
                    }

                    main()
                  })
                }
                asyncForEach(aAgentList, updateInfo).then(() => {
                  //delete
                  asyncForEach(dAgentList, deleteInfo).then(findResolve);
                });
              })
            }).then(() => {
              resolve2()
            }).catch(error => {
              console.log("Find agent error: " + error)
              reject2(error)
            })
          } else {
            //All agents are deleted
            agentInfoModel.findOneAndDelete({}).exec().then(() => {
              resolve2()
            }).catch(error => {
              console.log("Delete all error: " + err)
              reject2(error)
            })
          }
        } catch (error) {
          console.log("Read file error: " + error);
          reject2(error)
        }
      })
    }).then(() => {
      // console.log("Closing db - " + moment.now())
      mongoose.connection.close().then(() => {
        resolve()
      })
    }).catch((err) => {
      console.log("Connection Error 1: " + err)
      resolve()
    });
  })
}

async function initManagerInfo(ossec_path= ossecDir) {
  return new Promise((resolve,reject) => {
    mongoose.connect(url + "/" + globalDb).then(() => {
      return new Promise((resolve2, reject2) => {
        var db = mongoose.connection
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
            upsert: true,
            setDefaultsOnInsert: true
          }).exec((err, res) => {
            if (err) {
              console.log("Add manager error: " + err)
            } else {
              resolve2()
              // console.log(res)
            }
          })
        } catch (error) {
          console.log("Config File reading error: " + error)
          db.close().then(() => reject())
        }
      })
    }).then(() => {
      mongoose.connection.close().then(() => {
        resolve()
      })
    }).catch((err) => {
      console.log("Connection Error 2: " + err)
    });
  })
}

async function updateAgentInfoFromFile(filePath) {
  return new Promise((resolve, reject) => {
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
      mongoose.connect(url + "/" + globalDb).then(() => {
        return new Promise((connResolve, connReject) => {
          var db = mongoose.connection
          agentInfoModel.findOneAndUpdate({
            name: name,
            ip: ip,
          }, agentUpdateInfo, {
            new: true,
            upsert: false
          }).exec((err, res) => {
            if (err) {
              console.log("Update Error: " + err);
            } else {
              // console.log(res)
              connResolve()
            }
          })
        })
      }).then(() => {
        mongoose.connection.close().then(() => resolve())
      }).catch(err => {
        console.log("Connection Error 3: " + err)
        resolve()
      });
    } catch (error) {
      console.log("File Readind Error: " + error);
      resolve()
    }
  })
}

async function dropCollectionSync(db,name) {
  await mongoose.connect(url + "/" + db).then(() => {
    return new Promise((res, rej) => {
      mongoose.connection.db.listCollections({name: name}).next((lErr, collection) => {
        if (lErr) {
          console.log('Unable to get collections list: ' + lErr)
        } else if (typeof collection !== 'undefined') {
          if (collection != null && collection.name == name) {
            console.log(collection.name + " - " + name + " - " + moment.now())
            mongoose.connection.dropCollection(name).then(() => {
              console.log("Drop collection " + name + " from " + db)
              res()
            }).catch((error) => {
              console.log("Dropping " + collection + " Error: " + error + " - " + moment.now())
              rej()
            })
          }
        }
      })
      res()
    })
  }).then(() => {
    mongoose.connection.close()
  }).catch(reason => {
    console.log("Connecting db for dropping collection Error: " + reason)
  })
}

//read rootcheck
async function readRootcheck() {
  return new Promise((resolve, reject) => {
    try {
      var exist = fs.existsSync(rootcheckDir)
      if (exist) {
        filenames = fs.readdirSync(rootcheckDir)
        for (index in filenames) {
          var filename = filenames[index]
          filename = path.join(rootcheckDir, filename)
          if (!fs.statSync(filename).isFile()) continue
          var agentDb = ""

          filename = path.basename(filename)
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
              console.log("Read client.keys file error from rootcheck reading: " + error)
            }
          } else if (matchArr = filename.match(/^rootcheck$/)){
            agentDb = "000"
          } else {
            continue
          }

          dropCollectionSync(agentDb, 'pm_event')
          filename = path.join(rootcheckDir, filename)
          var child = child_process.spawn("tail", ["-f",'-n','+1', filename])
          child.stdout.setMaxListeners(100)
          var chunkLeftover = [""]
          child.stdout.on('data', logDataChunk => {
            // console.log("got data from a rootcheck file - " + agentDb)
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
            } else {
              chunkLeftover.push("")
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
            mongoose.connect(url + "/" + agentDb).then(() => {
              return new Promise((connResolve, connReject) => {
                // console.log("Inserting rootcheck event to " + agentDb)
                agentRootcheckModel.insertMany(pm_event_arr).then(() => {
                  mongoose.connection.close(connResolve)
                }).catch(error  => {
                  console.log('Insert pm event error: ' + error)
                  mongoose.connection.close().then(connReject)
                })
              })
            }).then(() => {
              child.stdout.resume()
            }).catch(err => {
              console.log("Connection Error: " + err)
              child.stdout.resume()
            })
            
          })

          child.on('close', code => {
            console.log(code)
          })

          childObj[filename] = child
        }
        console.log("Finish reading rootcheck - " + moment.now())
        resolve()
      } else {
        console.log("Rootcheck folder not exist")
        reject()
      }
    } catch (existError) {
      console.log("Unable to determine if rootcheck available or not: " + existError)
    }
  })
}

async function saveObjSync(obj) {
  return new Promise((resolve, reject) => {
    obj.save().then(newObj => {
      resolve(newObj)
    }).catch(sError => {
      reject(sError)
    })
  })
}

//read syscheck
async function readSyscheck() {
  return new Promise((resolve, reject) => {
    fs.exists(syscheckDir, exists => {
      if (exists) {
        fs.readdir(syscheckDir, (err, filenames) => {
          console.log("Begin reading syscheck - " + moment.now())
          if (err) {
            console.log("Read Syscheck dir Error: " + err)
          } else {
            filenames.forEach(filename => {
              filename = path.join(syscheckDir, filename)
              if (!fs.statSync(filename).isFile()) return
              var agentDb = ""
  
              filename = path.basename(filename)
              if (matchArr = filename.match(/\(?([^)]+)\)?\s?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?\-\>(syscheck|syscheck-registry)$/)) {
                var name = matchArr[1]
                var ip = matchArr[2]
                var type = matchArr[3]
  
                console.log(name)
                console.log(ip)
  
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
                  console.log("Read client.keys file error from syscheck reading: " + error)
                }
              } else if (matchArr = filename.match(/^syscheck$/)){
                agentDb = "000"
              } else {
                return
              }
  
              dropCollectionSync(agentDb, 'fim_event').then(() => {
                dropCollectionSync(agentDb, 'fim_file')
              })
              
              
              filename = path.join(syscheckDir, filename)
              var child = child_process.spawn("tail", ["-f", '-n', '+1', filename])
              child.stdout.setMaxListeners(100)
              var chunkLeftover = [""]
  
              child.stdout.on('data', logDataChunk => {
                console.log("got data from a syscheck file")
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
                  return new Promise((connResolve, connReject) => {
                    var db = mongoose.connection
                    for (index in logData) {
                    
                      var line = logData[index].toString().trim()
                      if (line.length > 0) {
                        // process line data 
                        if (match = line.match(/^(([#\+\!]{3})(\d+):(\d+):([^:\s]+):(\d+):([\w\d]+):([\w\d]+)|(\-1))\s\!(\d{10})\s(.+)$/)) {
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
                            perm = attr[3]
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
                          //get id_file and event
                          syscheckFileModel.findOne({
                            path: filePath,
                            type: type
                          }).exec().then(findRes => {
                            return new Promise((findResolve, findReject) => {
                              if (findRes) {
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
                                  findResolve()
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
                                // console.log('Inserting syscheck file to ' + agentDb)
                                
                                saveObjSync(newFimFile).then(fimFile => {
                                  if (fimFile != null) {
                                    id_file = fimFile._id
                                  }
                                }).then(() =>{
                                  findResolve()
                                }).catch((error) => {
                                  console.log("Saving fimFile Error: " + error)
                                  findReject(error)
                                })
                              }
                            })
                          }).then(() => {
                            console.log(id_file)
                            var newFimEvent = new syscheckEventModel({
                              file_id: id_file,
                              type: event,
                              date: time,
                              size: size,
                              perm: perm,
                              uid: uid,
                              gid: gid,
                              md5: md5,
                              sha1: sha1
                            })
                            // console.log('Inserting syscheck event to ' + agentDb)
                            saveObjSync(newFimEvent).then(fimEvent => console.log(fimEvent))
                            .catch((error) => console.log("Insert fimEvent error: " + error))
                          }).catch(findErr => {
                            console.log("Find Error: " + findErr)
                          })
                        }
                      }
                    }
                    connResolve()
                  })
                }).then(() => {
                  mongoose.connection.close()
                }).catch(reason => {
                  console.log("Connect Db Error: " + reason)
                })
                //continue the stream
                child.stdout.resume()
              })
  
              childObj[filename] = child
            })
          }
        })
        console.log("Finish reading syscheck - " + moment.now())
        resolve()
      } else {
        console.log("No syscheck folder")
        reject()
      }
    })
  })
}

// read files synchronously and get agent info
async function readFilesFirst() {
  await initManagerInfo();

  for (index in filesAndDir) {
    var fPath = filesAndDir[index]
    {
      // console.log(fPath)
      var isFile = false;;
      try {
        isFile = fs.statSync(fPath).isFile();
      } catch (error) {
        return;
      }
      if (isFile) {
        // client.keys
        await updateAgentBasicInfo(fPath);
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
                console.log(index)
                await callback(array[index])
              }
            }
  
            asyncForEach(fileNames, updateAgentInfoFromFile);
          } catch (error) {
            console.log(error);
          }
        } else if (fPath.indexOf("/queue/rootcheck/") > -1) {
          // await readRootcheck()
        } else if (fPath.indexOf("/queue/syscheck/") > -1) {
          // await readSyscheck()
        }
      }
    }
  }
}


// watcher will watch file asynchronously

async function watchFile(){
  var watcher = chokidar.watch(filesAndDir, {persistent: true, awaitWriteFinish: true, usePolling: true, atomic: true});

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
    console.log('File', fPath, 'has been changed');
    if (fPath.indexOf("/etc/client.keys") > -1) {
      updateAgentBasicInfo()      
    }
    else if (fPath.indexOf("/queue/agent-info/") > -1) {
      // agent info modified
      updateAgentInfoFromFile(fPath);    
    }
  })
  .on('unlink', function(fPath) {
    if (fPath.indexOf("/etc/client.keys") > -1) {
      //impossible

    }
    else if (fPath.indexOf("/queue/agent-info/") > -1) {
      // agent info deleted
      var filename = path.basename(fPath);
      var name = filename.split("-")[0];
      var ip = filename.split("-")[1];

      mongoose.connect(url + "/" + globalDb);
      var db = mongoose.connection;
      db.on('error', () => console.log("Connection Error 5: " + error))
      db.on('open', () => {
        agentInfoModel.findOneAndDelete({
          ip: ip,
          name: name
        }, (err, res) => {
          if (err) {
            console.log("Delete Error from unlink file: " + err);
          } else {

          }
        }).then(() => {
          db.close();
        })
      })
    } else if (fPath.indexOf("/queue/rootcheck/") > -1) {
      // if (match = fPath.match(/\(([^)]+)\)\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\-\>rootcheck$/)) {
      //   childObj[fPath].kill()

      // } else if (fPath.match(/^$rootcheck/)) {
      //   childObj[fPath].kill()
      //   dropCollectionSync('000','pm_event')
      // }
      
    } else if (fPath.indexOf("/queue/syscheck/") > -1) {
      // if (match = fPath.match(/\(?([^)]+)\)?\s?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?\-\>(syscheck|syscheck-registry)$/)) {
      //   childObj[fPath].kill()
      // } else if (fPath.match(/^syscheck$/)) {
      //   childObj[fPath].kill()
      // }
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

main()