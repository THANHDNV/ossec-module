#!/usr/bin/env node

const chokidar = require('chokidar');
const path = require('path');
const util = require('util');
const fs = require('fs');
const mongoose = require('mongoose');

var url =  "mongodb://127.0.0.1:27017";
var globalCollection = "global";
var agentCollection = "%s_%s";

var ossecDir = "/var/ossec";
var filesAndDir = [ossecDir + "/etc/client.keys", ossecDir + "/queue/agent-info/"];

//init mongoose schema and model
mongoose.Promise = global.Promise;
const Schema = mongoose.Schema;
var agentInfoSchema = Schema({
  id: String,
  name: String,
  ip: String,
  key: String,
  os: String,
  os_arch: String,
  version: String,
  config_sum: String,
  lastAlive: Date
});
agentInfoSchema.index({"id": 1});
var agentInfoModel = mongoose.model("agent", agentInfoSchema, "agent");

// read files synchronously and get agent info
async function readFilesFirst() {
  filesAndDir.forEach((fPath, index) => {
    var isFile = false;;
    try {
      isFile = fs.statSync(fPath).isFile();
    } catch (error) {
      return;
    }
    if (isFile) {
      // client.keys
      try {
        var data = fs.readFileSync(fPath, 'utf8');

        //connect to db
        mongoose.connect(url + "/" + globalCollection);
        var db = mongoose.connection;

        db.on('error', err => console.log("Connection Error: " + err));
        db.once('open', () => {
          //process data
          var lines = data.toString().trim().split("\n");

          var validAgentList = [];

          async function pushToAgentList (doc) {
            
              validAgentList.push(doc);
            
          }

          async function addDocsToCollection (line) {
            var agentInfoArray = line.split(" ");
            var agentObj = {
              $setOnInsert: {
                id: agentInfoArray[0].toString().trim(),
                name: agentInfoArray[1].toString().trim(),
              },
              $set: {
                ip: agentInfoArray[2].toString().trim(),
                key: agentInfoArray[3].toString().trim(),
              }              
            };
            agentInfoModel.findOneAndUpdate({
              id: agentInfoArray[0].toString().trim(),
              name: agentInfoArray[1].toString().trim()},
              agentObj, {new: true, upsert: true}, (err, doc, res) => {
                if (err) {
                  console.log("Find and Update Error: " + err);
                } else {
                  // console.log("\n\n\nResult:")
                  // console.log(doc);
                  // console.log(res);
                  // console.log("\n\n\n\n");
                  // pushToAgentList(doc);
                }
              })
          }

          async function asyncForEach(array, callback) {
            for (let index = 0; index < array.length; index++) {
              await callback(array[index])
            }
          }

          asyncForEach(lines, addDocsToCollection).then(() => {
            agentInfoModel.find({}).then((agentList) => {
              // console.log(agentList)
              // console.log()
              // console.log(validAgentList)
              // console.log()
              //filter before delete
              var filtered = agentList.filter(agent => {
                var found = validAgentList.find(vAgent => vAgent.id == agent.id && vAgent.name == agent.name);
                return typeof found === 'undefined'
              })
              // console.log(filtered);
  
              //delete
              filtered.forEach((agent) => {
                if (!(agent in validAgentList)) {
                  agentInfoModel.deleteOne(agent, err => console.log('Delete Error: ' + err));
                } else {
                }
              })
  
            }).then(() => {
              //close the database
              db.close();
            })
          })

          // delete agents not in client.keys
          
        })
      } catch (error) {
        console.log("File Reading Error: " + error)
      }
    } else {
      //other folders
      if (fPath.indexOf("/queue/agent-info") > -1) {
        //read each files in agent-info
        try {
          const dirName = "/queue/agent-info/";
          var fileNames = fs.readdirSync(fPath, "utf8");

          async function updateagentInfoFromFile(filename) {
            var filePath = path.join(fPath, filename)
            var isFile = fs.statSync(filePath);
            if (isFile) {
              async function getOsArch(os) {
                return new Promise((res, rej) => {
                  var archs = [ "x86_64", "i386", "i686", "sparc", "amd64", "ia64", "AIX", "armv6", "armv7", "" ]
                  for (i = 0; i < archs.length; i++) {
                    if (os.indexOf(archs[i]) > -1) {
                      res(archs[i]);
                    }
                  }
                })
              }

              var data = fs.readFileSync(filePath, 'utf8');
              var name = filename.split("-")[0];
              var ip = filename.split("-")[1];

              var os_arch = await getOsArch(data)
              var mTime = fs.statSync(filePath).mtime;
              var ossecVersionArr = data.split(" - ")[1].split(" / ").push("");
              var version = ossecVersionArr[0];
              var configSum = ossecVersionArr[1];

              //create update info obj
              var agentUpdateInfo = {
                $set: {
                  os: data,
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
              console.log(agentUpdateInfo)

              //connect to mongodb
              mongoose.connect(url + "/" + globalCollection);
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
                    // console.log();
                  }
                }).then(() => {
                  db.close();
                })
              })
            }
          }

          async function asyncForEach(array, callback) {
            for (let index = 0; index < array.length; index++) {
              await callback(array[index])
            }
          }

          asyncForEach(fileNames, updateagentInfoFromFile);
        } catch (error) {
          console.log(error);
        }
      } else if (path.indexOf("/queue/rootcheck/") > -1) {

      } else if (path.indexOf("/queue/syscheck/") > -1) {
        
      }
    }
  })
}

// watcher will watch file asynchronously

async function watchFile(){
  var watcher = chokidar.watch(filesAndDir, {persistent: true});

watcher
  .on('add', function(fPath, stat) {
    console.log("File ", fPath, " has been added")
    if (fPath.indexOf("/etc/client.keys") > -1) {

    } else if (fPath.indexOf("/queue/agent-info/") > -1) {
    
    } else if (fPath.indexOf("/queue/rootcheck/") > -1) {

    } else if (fPath.indexOf("/queue/syscheck/") > -1) {

    }
  })
  .on('change', function(fPath, stat) {
    console.log('File', path, 'has been changed');
    if (fPath.indexOf("/etc/client.keys")) {

      mongoose.connect(url + "/" + globalCollection);
      var db = mongoose.connection;
      db.on('error', err => console.log("Connection Error: " + err));
      db.on('open', () => {
        var data = "";

        try {
          data = fs.readFile(fPath, 'utf8');
          var lines = data.trim().split("\n");
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
                  return agent.id == id && agent.name == name
                })
                return (typeof found === 'undefined')
              })

              //modify agent info
              //add or update
              aAgentList.forEach(line => {
                var agentInfoArray = line.toString.split(' ');
                var agentObj = {
                  $set: {
                    name: agentInfoArray[1],
                    ip: agentInfoArray[2],
                    key: agentInfoArray[3]
                  },
                  $setOnInsertl: {
                    id: agentInfoArray[0],
                  }
                }
                agentInfoModel.findOneAndUpdate({
                  id: agentInfoArray[0]
                }, agentObj, {
                  new: true,
                  upsert: true,

                }, (err, doc, res) => {
                  if (err) {
                    console.log("Update Error: " + err)
                  } else {
                    // console.log(doc)
                  }
                })
              })

              //delete
              dAgentList.forEach(agent => {
                agentInfoModel.findOneAndDelete({
                  id: agent.id
                }, (err, res) => {
                  if (err) {
                    console.log("Delete Error: " + err)
                  } else {
                    // console.log(res);
                  }
                })
              })
            }, rej => {
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
            })
          }
        } catch (error) {
          console.log("Read file error: " + error);
        } finally {
          db.close(); 
        }
      })
    }
    else if (fPath.indexOf("/queue/agent-info/") > -1) {
    
    } else if (fPath.indexOf("/queue/rootcheck/") > -1) {

    } else if (fPath.indexOf("/queue/syscheck/") > -1) {

    }
  })
  .on('unlink', function(fPath) {console.log('File', path, 'has been removed');})
  .on('error', function(error) {console.error('Error happened', error);})
}

//calling main
async function main() {
  readFilesFirst().then(watchFile);
}

main();