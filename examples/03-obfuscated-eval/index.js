// a benign-looking formatter whose payload is decoded and executed
const payload = "ZXZhbChhdG9iKCJjb25zb2xlLmxvZygncGwnKSIpKQ==";
eval(atob(payload));
