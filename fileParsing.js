#!/usr/bin/env node

const chokidar = require('chokidar');
const path = require('path');
const util = require('util');
const fs = require('fs');
const mongoose = require('mongoose');
const uname = require('node-uname')
const child_process = require('child_process')
const moment = require('moment')
const { MongooseAutoIncrementID } = require('mongoose-auto-increment-reworked')
const os = require("os");

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

const options = {
  field: '_id',
  increment: 1,
  nextCount: 'nextCount',
  resetCount: false,
  startAt: 1,
  unique: false
}

const agentRootcheckSchema = Schema({
  date_first: Date,
  date_last: Date,
  log: String,
  pci_dss: String
})
// var rootcheckFilePlugin = new MongooseAutoIncrementID(agentRootcheckSchema, 'agentRootcheckModel', options)
// rootcheckFilePlugin.applyPlugin()
const agentRootcheckModel = mongoose.model("rootcheck", agentRootcheckSchema, "pm_event")

const syscheckFileSchema = Schema({
  path: String,
  type: String
})
// var syscheckFilePlugin = new MongooseAutoIncrementID(syscheckFileSchema, 'syscheckFileModel', options)
// syscheckFilePlugin.applyPlugin()
const syscheckFileModel = mongoose.model('syscheck-file', syscheckFileSchema, "fim_file")

const syscheckEventSchema = Schema({
  file_id: Object,
  type: String,
  date: Date,
  size: Number,
  perm: Number,
  uid: String,
  gid: String,
  md5: String,
  sha1: String
})
// var syscheckEventPlugin = new MongooseAutoIncrementID(syscheckEventSchema, 'syscheckEventModel', options)
// syscheckEventPlugin.applyPlugin()
const syscheckEventModel = mongoose.model('syscheck', syscheckEventSchema, 'fim_event')

const pmCounterInfoSchema = Schema({
  pm_event_counter: {
    type: Number,
    default: 0
  }
})
const pmCounterInfoModel = mongoose.model('pmCounterInfo', pmCounterInfoSchema, 'pmCounterInfo');

const fimCounterInfoSchema = Schema({
  fim_event_counter: {
    type: Number,
    default: 0
  },
  fim_file_counter: {
    type: Number,
    default: 0
  }
})
const fimCounterInfoModel = mongoose.model('fimCounterInfo', fimCounterInfoSchema, 'fimCounterInfo');

//agent CRUD

async function updateAgentBasicInfo(fPath = ossecDir + "/etc/client.keys") {
  return new Promise((resolve, reject) => {
    mongoose.connect(url + "/" + globalDb).then(() => {
      return new Promise((resolve2, reject2) => {
        var data = "";
        // console.log(fPath)
        try {
          data = fs.readFileSync(fPath, 'utf8');
          var lines = data.trim().split(/\r?\n/);
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
      console.log("Closing db at updateAgentBasicInfo - " + moment.now())
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
          console.log("Closing db at initManagerInfo inner - " + moment.now())
          db.close().then(reject)
        }
      })
    }).then(() => {
      console.log("Closing db at initManagerInfo - " + moment.now())
      mongoose.connection.close().then(resolve)
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
        console.log("Closing db at updateAgentInfoFromFile - " + moment.now())
        mongoose.connection.close().then(resolve)
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
  return new Promise((resolve, reject) => {
    mongoose.connect(url + "/" + db).then(async () => {
      console.log("Connected to " + url + "/" + db)
      return new Promise((res, rej) => {
        mongoose.connection.db.listCollections({name: name}).next((lErr, collection) => {
          if (lErr) {
            console.log('Unable to get collections list: ' + lErr)
            rej();
          } else if (typeof collection !== 'undefined') {
            if (collection != null && collection.name == name) {
              console.log(collection.name + " - " + name + " - " + moment.now())
              mongoose.connection.db.dropCollection(name).then(() => {
                console.log("Drop collection " + name + " from " + db)
                mongoose.connection.close().then(res);
              }).catch((error) => {
                console.log("Dropping " + collection.name + " Error: " + error + " - " + moment.now())
                rej()
              })
            } else {
              console.log('Collection null');
              res();
            }
          } else {
            console.log("IDK")
            res();
          }
        })
      })
    }).then(() => {
      console.log("Closing db at dropCollectionSync - " + db + "/" + name + " - " + moment.now())
      mongoose.connection.close();
      resolve();
    }).catch(reason => {
      console.log("Connecting db for dropping collection Error: " + reason)
      resolve();
    })
  });
}

function getAgentDbFromRootcheckFile(filename) {
  var agentDb = ""
  var basename = path.basename(filename)
  if (matchArr = basename.match(/\(([^)]+)\)\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\-\>rootcheck$/)) {
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
  } else if (matchArr = basename.match(/^rootcheck$/)){
    agentDb = "000"
  } else {
  }
  return agentDb;
}

//read rootcheck file
async function readRootcheckFile(filename) {
  return new Promise ((resolve, reject) => {
    try {
      agentDb = getAgentDbFromRootcheckFile(filename);
      if (agentDb != "") {
        mongoose.connect(url + "/" + agentDb).then(() => {
          return new Promise((connResolve, connReject) => {
            // console.log("Inserting rootcheck event to " + agentDb)
            pmCounterInfoModel.findOne().exec().then(pmCounterInfo => {
              return new Promise((countFindResolve, countFindReject) => {
                var rCount = 0;
                if (pmCounterInfo) {
                  rCount = pmCounterInfo.pm_event_counter;
                }
                console.log("rCount: " + rCount);
                var logs = fs.readFileSync(filename, 'utf-8').trim();
                
                var logData = logs.split(/[\r\n]+/);
                
                var logDataArr = logData.slice(rCount);
                console.log(logDataArr[0]);
                var pm_event_arr = []
                
                for (index in logDataArr) {
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
                      date_first: end_time,
                      date_last: start_time,
                      log: log,
                      pci_dss: pci_dss
                    }

                    pm_event_arr.push(event)
                  }
                }
                console.log(pm_event_arr.length);
                agentRootcheckModel.insertMany(pm_event_arr).then(() => {
                  console.log("Closing db at inserting pm-event " + agentDb + " - " + moment.now())
                  pmCounterInfoModel.findOneAndUpdate({}, {$inc: { pm_event_counter: pm_event_arr.length} }, {
                    new: true,
                    upsert: true,
                    setDefaultsOnInsert: true
                  }).exec().then((res) => {
                    console.log(res + " - " + moment.now())
                    mongoose.connection.close().then(countFindResolve);
                  }).catch(incError => {
                    console.log("Increase pm_event counter error: " + incError);
                    mongoose.connection.close().then(countFindReject);
                  })
                }).catch(error  => {
                  console.log('Insert pm event error: ' + error)
                  mongoose.connection.close().then(countFindReject);
                })
              })
            }).then(connResolve).catch(error => {
              console.log('Getting next rootcheck event counter error: ' + error)
              mongoose.connection.close().then(connReject)
            })
          })
        }).then(() => {
          resolve();
        }).catch(err => {
          console.log("Connection Error: " + err)
          resolve()
        })
      } else {
        resolve();
      }
    } catch (error) {
      console.log("Unable to read rootcheck file: " + error);
      resolve();
    }
  })
}

//read rootcheck
async function readRootcheck() {
  return new Promise(async (resolve, reject) => {
    try {
      var exist = fs.existsSync(rootcheckDir)
      if (exist) {
        filenames = fs.readdirSync(rootcheckDir)
        for (index in filenames) {
          var filename = filenames[index]
          filename = path.join(rootcheckDir, filename)
          if (!fs.statSync(filename).isFile()) continue
          var agentDb = getAgentDbFromRootcheckFile(filename);
          if (agentDb != '') {
            console.log("ready to drop database " + agentDb + ": " + moment.now());
            await dropCollectionSync(agentDb, 'pm_event');
            await dropCollectionSync(agentDb, 'pmCounterInfo');
            console.log('Dropped db');

            //reading file
            console.log('Reading rootcheck file ' + moment.now())
            await readRootcheckFile(filename)
            console.log('Finish reading rootcheck file ' + filename);
          }
        }
        console.log("Finish reading rootcheck - " + moment.now())
        resolve()
      } else {
        console.log("Rootcheck folder not exist")
        reject()
      }
    } catch (existError) {
      console.log("Unable to determine if rootcheck available or not: " + existError)
      reject();
    }
  })
}

function getAgentDbFromSyscheckFile(filename) {
  var agentDb = ""
  var basename = path.basename(filename)
  if (matchArr = basename.match(/\(([^)]+)\)\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\-\>(syscheck|syscheck-registry)$/)) {
    var name = matchArr[1]
    var ip = matchArr[2]
    

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
  } else if (matchArr = basename.match(/^syscheck$/)){
    agentDb = "000"
  } else {
  }
  return agentDb;
}

async function readSyscheckFile(filename) {
  return new Promise ((resolve, reject) => {
    try {
      agentDb = getAgentDbFromSyscheckFile(filename);
      
      if (agentDb != "") {
        var basename = path.basename(filename)
        var type = '';
        if (matchArr = basename.match(/\(([^)]+)\)\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\-\>(syscheck|syscheck-registry)$/)) {
          type = matchArr[3]
        } else if (matchArr = basename.match(/^syscheck$/)){
          type = 'syscheck'
        }

        if (type == 'syscheck') {
          type = 'file'
        }
        mongoose.connect(url + "/" + agentDb).then(() => {
          return new Promise((connResolve, connReject) => {
            // console.log("Inserting Syscheck event to " + agentDb)
            fimCounterInfoModel.findOne().exec().then(fimCounterInfo => {
              return new Promise(async (countFindResolve, countFindReject) => {
                var rCount = 0;
                if (fimCounterInfo) {
                  rCount = fimCounterInfo.fim_event_counter;
                }
                var logs = fs.readFileSync(filename, 'utf-8').trim();
                var logData = logs.split('\n');

                logData = logData.slice(rCount);

                var fim_event_arr = []

                for (index in logData) {
                  var line = logData[index].trim()
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
                      //this part is not synchronouse

                      try {
                        var findRes = await syscheckFileModel.findOne({
                          path: filePath,
                          type: type
                        }).exec();
                        if (findRes) {
                          // have existed
                          // look for the file events in db
                          id_file = findRes._id

                          var docs = await syscheckEventModel.find({
                            file_id: id_file
                          }).sort({ _id: -1 }).limit(1).exec();
                          if (docs) {
                            // found last event of the file
                            //suppose to have 1 and only 1 doc
                            console.log(docs.length)
                            if (docs.length == 1) {
                              var doc = docs[0]
                              if (doc.event == "added" || doc.event == 'modified' || doc.event =='readded') {
                                event = 'modified'
                              } else {
                                event = 'readded'
                              }
                            } else {
                              console.log('This is odd: ' + findRes.path + ' - ' + findRes.type)
                            }
                          } else {
                            // no event was found - impossible since inserting into pim_file will also insert an event into fim_event
                          }
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
                          var fimFile = await newFimFile.save();
                          if (fimFile != null) {
                            id_file = fimFile._id
                          }
                          var fimCounterInfo = await fimCounterInfoModel.findOneAndUpdate({}, {$inc: { fim_file_counter: 1} }, {
                            new: true,
                            upsert: true,
                            setDefaultsOnInsert: true
                          }).exec();
                        }
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
                        var fimEvent = await newFimEvent.save();
                        if (fimEvent != null) {
                          var fimCounterInfo = await fimCounterInfoModel.findOneAndUpdate({}, {$inc: { fim_event_counter: 1} }, {
                            new: true,
                            upsert: true,
                            setDefaultsOnInsert: true
                          }).exec();
                        }
                        // fim_event_arr.push(newFimEvent);
                      } catch (findErr) {
                        console.log("Find Error: " + findErr)
                      }

                      // syscheckFileModel.findOne({
                      //   path: filePath,
                      //   type: type
                      // }).exec().then(findRes => {
                      //   return new Promise((findResolve, findReject) => {
                      //     if (findRes) {
                      //       // have existed
                      //       // look for the file events in db
                      //       id_file = findRes._id
                      //       syscheckEventModel.find({
                      //         id_file: id_file
                      //       }).sort({ _id: -1 }).limit(1).exec().then((docs) => {
                      //         if (docs) {
                      //           // found last event of the file
                      //           //suppose to have 1 and only 1 doc
                      //           if (docs.length == 1) {
                      //             var doc = docs[0]
                      //             if (doc.event == "added" || doc.event == 'modified' || doc.event =='readded') {
                      //               event = 'modified'
                      //             } else {
                      //               event = 'readded'
                      //             }
                      //           }
                      //         } else {
                      //           // no event was found - impossible since inserting into pim_file will also insert an event into fim_event
                      //         }
                      //         findResolve()
                      //       }).catch(fErr => {
                      //         console.log("Find fim file error: " + fErr)
                      //         findReject(fErr);
                      //       })
                      //     } else {
                      //       //file not existed in db
                      //       if (eventCode[0] == "+" || (eventCode[0] == '#' && eventCode[1] == '+')) {
                      //         event = "added"
                      //       } else {
                      //         event = "modified"
                      //       }
                      //       //save new file to fim_file
                      //       var newFimFile = new syscheckFileModel({
                      //         path: filePath,
                      //         type: type
                      //       })
                      //       // console.log('Inserting syscheck file to ' + agentDb)
                            
                      //       newFimFile.save().then(fimFile => {
                      //         return new Promise((sResolve, sReject) => {
                      //           if (fimFile != null) {
                      //             id_file = fimFile._id
                      //           }
                      //           fimCounterInfoModel.findOneAndUpdate({}, {$inc: { fim_file_counter: 1} }, {
                      //             new: true,
                      //             upsert: true,
                      //             setDefaultsOnInsert: true
                      //           }).exec().then((fimCounterInfo) => {
                                  
                      //             sResolve();
                      //           }).catch(sReject);
                      //         })
                      //       }).then(findResolve).catch(sError => {
                      //         console.log("Unable to save fimFile: " + sError);
                      //         findReject(sError);
                      //       })
                      //     }
                      //   })
                      // }).then(() => {
                      //   var newFimEvent = {
                      //     file_id: id_file,
                      //     type: event,
                      //     date: time,
                      //     size: size,
                      //     perm: perm,
                      //     uid: uid,
                      //     gid: gid,
                      //     md5: md5,
                      //     sha1: sha1
                      //   }
                      //   fim_event_arr.push(newFimEvent);
                      // }).catch(findErr => {
                      //   console.log("Find Error: " + findErr)
                      // })
                    }
                  }
                }
                console.log('Add all line from file ' + filename + ' - ' + moment.now())
                mongoose.connection.close().then(countFindResolve);
                // console.log(fim_event_arr.length)
                // syscheckEventModel.insertMany(fim_event_arr).then(() => {
                //   console.log("Closing db at inserting fim-event " + agentDb + " - " + moment.now())
                //   fimCounterInfoModel.findOneAndUpdate({}, {$inc: { fim_event_counter: fim_event_arr.length} }, {
                //     new: true,
                //     upsert: true,
                //     setDefaultsOnInsert: true
                //   }).exec().then((res) => {
                //     console.log(res + " - " + moment.now())
                //     mongoose.connection.close().then(countFindResolve);
                //   }).catch(incError => {
                //     console.log("Increase fim_event counter error: " + incError);
                //     mongoose.connection.close().then(countFindReject);
                //   })
                // }).catch(error  => {
                //   console.log('Insert fim event error: ' + error)
                //   mongoose.connection.close().then(countFindReject);
                // })
              })
            }).then(connResolve).catch(error => {
              console.log('Getting next syscheck event counter error: ' + error)
              mongoose.connection.close().then(connReject)
            })
          })
        }).then(() => {
          resolve();
        }).catch(err => {
          console.log("Connection Error: " + err)
          resolve()
        })
      } else {
        resolve();
      }
    } catch (error) {
      console.log("Unable to read syscheck file: " + error);
      resolve();
    }
  })
}

//read syscheck
async function readSyscheck() {
  return new Promise(async (resolve, reject) => {
    try {
      var exist = fs.existsSync(syscheckDir);
      if (exist) {
        filenames = fs.readdirSync(syscheckDir)
        for (index in filenames) {
          var filename = filenames[index]
          filename = path.join(syscheckDir, filename)
          if (!fs.statSync(filename).isFile()) continue
          var agentDb = getAgentDbFromSyscheckFile(filename);
          if (agentDb != '') {
            await dropCollectionSync(agentDb, 'fim_event');
            await dropCollectionSync(agentDb, 'fim_file');
            await dropCollectionSync(agentDb, 'fimCounterInfo');
            
            await readSyscheckFile(filename);
          }
        }
        console.log("Finish reading syscheck - " + moment.now())
        resolve()
      } else {
        console.log("Syscheck folder not exist")
        reject()
      }
    } catch (existError) {
      console.log("Unable to determine if syscheck available or not: " + existError)
      reject();
    }
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

            for (index in fileNames) {
              await updateAgentInfoFromFile(fileNames[index]);
            }

          } catch (error) {
            console.log(error);
          }
        } else if (fPath.indexOf("/queue/rootcheck/") > -1) {
          await readRootcheck()
        } else if (fPath.indexOf("/queue/syscheck/") > -1) {
          await readSyscheck()
        }
      }
    }
  }
}


// watcher will watch file asynchronously

async function watchFile(){
  var watcher = chokidar.watch(filesAndDir, {persistent: true, awaitWriteFinish: { stabilityThreshold: 5000, pollInterval: 200 }, usePolling: true, atomic: true});

watcher
  .on('add',async function(fPath, stat) {
    //File is added to watcher list
    console.log("File ", fPath, " has been added")
    if (fPath.indexOf("/etc/client.keys") > -1) {

    } else if (fPath.indexOf("/queue/agent-info/") > -1) {
      //Add new agent info
      await updateAgentInfoFromFile(fPath);
    }
  })
  .on('change',async function(fPath, stat) {
    //File on watcher list changed
    console.log('File', fPath, 'has been changed');
    if (fPath.indexOf("/etc/client.keys") > -1) {
      await updateAgentBasicInfo()
    }
    else if (fPath.indexOf("/queue/agent-info/") > -1) {
      // agent info modified
      await updateAgentInfoFromFile(fPath);
    } else if (fPath.indexOf("/queue/rootcheck/") > -1) {
      await readRootcheckFile(fPath);
    }  else if (fPath.indexOf("/queue/syscheck/") > -1) {
      await readSyscheckFile(fPath);
    }
  })
  .on('unlink',async function(fPath) {
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
      await dropCollectionSync(agentDb, 'pm_event');
      await dropCollectionSync(agentDb, 'pmCounterInfo');
    } else if (fPath.indexOf("/queue/syscheck/") > -1) {
      // if (match = fPath.match(/\(?([^)]+)\)?\s?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?\-\>(syscheck|syscheck-registry)$/)) {
      //   childObj[fPath].kill()
      // } else if (fPath.match(/^syscheck$/)) {
      //   childObj[fPath].kill()
      // }
      await dropCollectionSync(agentDb, 'fim_event');
      await dropCollectionSync(agentDb, 'fim_file');
      await dropCollectionSync(agentDb, 'fimCounterInfo');
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