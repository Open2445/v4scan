// legitimate-looking loader
const payload = "eyJhIjoxfQ==";
function run() {
  eval(atob(payload));
}
run();
