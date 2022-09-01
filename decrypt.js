const decipher = (data) => {
  if (data.api_key !== config.encrypt.api_key) return;

  const b64_data = Buffer.from(data.data, 'base64');
  const iv = b64_data.slice(0,16);
  let decipher = crypto.createDecipheriv(config.encrypt.algo,config.encrypt.key,iv);

  new_data = decipher.update(b64_data.slice(16,b64_data.length),'base64','utf8');
  new_data += decipher.final('utf8');

  return new_data;
}

