var config = require("../config/development");
var thinky = require('thinky')(config.rethinkdb);
module.exports = thinky;