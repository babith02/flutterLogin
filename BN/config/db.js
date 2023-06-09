const mongoose = require('mongoose');
const MONGO_URI = 'mongodb://127.0.0.1:27017/app';

exports.connect = () => {
    mongoose.connect( MONGO_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        useCreateIndex: true,
        useFindAndModify: false,
    })
    .then(() => {
        console.log("Successfully connected to database");
    })
    .catch((error) => {
        console.log("database connection failed. exiting now...");
        console.error(error);
        process.exit(1);
    });
}
