#!/usr/bin/env node

const chokidar = require('chokidar');
const mongoClient = require('mongodb').MongoClient;
const util = require('util');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');

console.log("Start");
var url =  "mongodb://127.0.0.1:27017";
var globalCollection = "global";
var agentCollection = "%s_%s";

var ossecDir = "/var/ossec";
var filesAndDir = [ossecDir + "/etc/client.keys", ossecDir + "/queue/agent-info/"];

async function main() {
  var watcher = chokidar.watch(filesAndDir, {persistent: true});

  watcher
    .on('add', function(fPath, stat) {
      console.log("File ", fPath, " has been added")
      if (fPath.indexOf("client.keys") > -1) {
        fs.readFile(fPath, (err, data) => {
          if (!err) {
            mongoose.connect(url + "/" + globalCollection);
            mongoose.Promise = global.Promise;
            var db = mongoose.connection;

            db.on('error', err => console.log("Connection Error: " + err));
            db.once('open', () => {
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
                merge_sum: String,
                lastAlive: Date
              });

              agentInfoSchema.index({"id": 1, "name": 1});

              var agentInfoModel = mongoose.model("agent", agentInfoSchema, "agent");
              
              var lines = data.toString().trim().split("\n");

              var validAgentList = [];

              var addDocsToCollection = (line) => {
                var agentInfoArray = line.split(" ");
                var agentObj = new agentInfoModel({
                  id: agentInfoArray[0].toString().trim(),
                  name: agentInfoArray[1].toString().trim(),
                  ip: agentInfoArray[2].toString().trim(),
                  hashed: agentInfoArray[3].toString().trim(),
                });
                agentInfoModel.findOneAndUpdate({
                  id: agentInfoArray[0].toString().trim(),
                  name: agentInfoArray[1].toString().trim()},
                  agentObj, {new: true, upsert: true})
                  .then((fuErr, fuRes) => {
                    if (fuErr) {
                      console.log("Find & Update Error: " + fuErr);
                    } else {
                      validAgentList.push(fuRes);
                    }
                })
              }

              const asyncDo = (value, cb) => {
                cd(line);
              }

              var doAddDocsToCollection = (line) => {
                asyncDo(line, addDocsToCollection);
              }

              lines.forEach(doAddDocsToCollection);

              // delete agents not in client.keys
              agentInfoModel.find({}).then((agentList) => {
                agentList.forEach((agent) => {
                  var agentInfo = {}
                  if (!(agent in validAgentList)) {
                    agentInfoModel.deleteOne(agent);
                  }
                })
              }).then(() => {
                mongoose.connection.close();
              })
            })
            }
          })
      } else if (fPath.indexOf("/queue/agent-info/") > -1) {
        var fPathArray = fPath.split("/");
        var fName = fPathArray[fPathArray.length - 1];
        var id = fName.split("_")[0];
        var name = fName.split("_")[1];

        
        mongoose.connect(url + "/" + globalCollection);
        mongoose.Promise = global.Promise;

        var db = mongoose.connection;
        db.on("error", err => console.log("Connection Error: " + err));
        db.on("open", () => {
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
            merge_sum: String,
            lastAlive: Date
          });

          agentInfoSchema.index({"id": 1, "name": 1});

          var agentInfoModel = mongoose.model("agent", agentInfoSchema, "agent");

          // get agent info from file
          
          var agentInfo = new agentInfoModel({
            id: id,
            name: name,
          })


          
        })

      } else if (fPath.indexOf("/queue/rootcheck/") > -1) {

      } else if (fPath.indexOf("/queue/syscheck/") > -1) {

      } else {
        console.log("Something's not right");
      }
    })
    .on('change', function(fPath, stat) {
      // console.log('File', path, 'has been changed');
    })
    .on('unlink', function(fPath) {console.log('File', path, 'has been removed');})
    .on('error', function(error) {console.error('Error happened', error);})
}

main()