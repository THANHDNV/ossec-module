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

//agent CRUD
async function updateAgentBasicInfo(fPath = ossecDir + "/etc/client.keys") {
  mongoose.connect(url + "/" + globalCollection);
  var db = mongoose.connection;
  db.on('error', err => console.log("Connection Error: " + err));
  db.on('open', () => {
    var data = "";

    console.log(fPath)
    try {
      data = fs.readFileSync(fPath, 'utf8');
      var lines = data.trim().split("\n");
      console.log(lines);
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
          async function updateInfo(line) {
            var agentInfoArray = line.toString().split(' ');
            var agentObj = {
              $set: {
                name: agentInfoArray[1],
                ip: agentInfoArray[2],
                key: agentInfoArray[3]
              },
              $setOnInsert: {
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
    var ossecVersionArr = data.split(" - ")[1].split(" / ");
    ossecVersionArr.push("")
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
    //File is added to watcher list
    console.log("File ", fPath, " has been added")
    if (fPath.indexOf("/etc/client.keys") > -1) {

    } else if (fPath.indexOf("/queue/agent-info/") > -1) {
      //Add new agent info
      updateAgentInfoFromFile(fPath);
    } else if (fPath.indexOf("/queue/rootcheck/") > -1) {

    } else if (fPath.indexOf("/queue/syscheck/") > -1) {

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
    } else if (fPath.indexOf("/queue/rootcheck/") > -1) {

    } else if (fPath.indexOf("/queue/syscheck/") > -1) {

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

      mongoose.connect(url + "/" + globalCollection);
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