const fs = require('fs');
const mongoose = require('mongoose');
const util = require('util');

mongoose.connect("mongodb://127.0.0.1:27017/global");
for (i = 0; i<1000; i++) {
}

var db = mongoose.connection;
db.on('error', err => console.log(err))
db.on('connect', () => {
    console.log('Connected');
})

// console.log(util.inspect(db, {depth: 5}));
mongoose.disconnect();

