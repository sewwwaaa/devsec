db = db.getSiblingDB('nodegoat');

db.createCollection('users');
db.createCollection('memos');
db.createCollection('allocation');
db.createCollection('benefits');
db.createCollection('research');

print('MongoDB initialized for NodeGoat');
