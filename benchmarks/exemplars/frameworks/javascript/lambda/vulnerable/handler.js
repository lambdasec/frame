'use strict';

const AWS = require('aws-sdk');
const { execSync } = require('child_process');
const mysql = require('mysql2/promise');
const axios = require('axios');

const s3 = new AWS.S3();

module.exports.getOrder = async (event) => {
  const orderId = event.pathParameters.id;
  const conn = await mysql.createConnection({ host: process.env.DB_HOST, user: 'api' });
  const [rows] = await conn.query("SELECT * FROM orders WHERE id = '" + orderId + "'");  // frame-expect: CWE-89
  return { statusCode: 200, body: JSON.stringify(rows) };
};

module.exports.fetchPreview = async (event) => {
  const target = event.queryStringParameters.url;
  const res = await axios.get(target);  // frame-expect: CWE-918
  return { statusCode: 200, body: res.data };
};

exports.resize = async (event, context) => {
  const payload = JSON.parse(event.body);
  execSync('convert ' + payload.key + ' -resize 50% /tmp/out.png');  // frame-expect: CWE-78
  return { statusCode: 202 };
};

exports.s3Hook = async (event) => {
  const key = event.Records[0].s3.object.key;
  execSync('clamscan /tmp/' + key);  // frame-expect: CWE-78
};
