require('dotenv').config();

const { MongoClient } = require('mongodb');

async function connectToDatabase() {
  const uri = `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@${process.env.MONGO_HOST}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority`;
  const client = new MongoClient(uri);
  
  try {
    await client.connect();
    console.log('Connected to MongoDB');
    return client.db(process.env.MONGODB_DATABASE);
  } catch (error) {
    console.error('Connection error:', error);
    process.exit(1);
  }
}

module.exports = connectToDatabase;