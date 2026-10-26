'use strict';

const AWS = require('aws-sdk');
const { execFileSync } = require('child_process');
const mysql = require('mysql2/promise');
const axios = require('axios');

const s3 = new AWS.S3();

module.exports.getOrder = async (event) => {
  const orderId = event.pathParameters.id;
  const conn = await mysql.createConnection({ host: process.env.DB_HOST, user: 'api' });
  const [rows] = await conn.query('SELECT * FROM orders WHERE id = ?', [orderId]);
  return { statusCode: 200, body: JSON.stringify(rows) };
};

const ALLOWED_URLS = ['https://api.example.com/status', 'https://cdn.example.com/banner.json'];

module.exports.fetchPreview = async (event) => {
  const target = event.queryStringParameters.url;
  if (!ALLOWED_URLS.includes(target)) {
    return { statusCode: 400 };
  }
  const res = await axios.get(target);
  return { statusCode: 200, body: res.data };
};

exports.resize = async (event, context) => {
  const payload = JSON.parse(event.body);
  execFileSync('convert', [payload.key, '-resize', '50%', '/tmp/out.png']);
  return { statusCode: 202 };
};

exports.s3Hook = async (event) => {
  const key = event.Records[0].s3.object.key;
  execFileSync('clamscan', ['/tmp/' + key]);
};
