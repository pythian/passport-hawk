module.exports = process.env.COVER
  ? require('./lib-cov/strategy')
  : require('./lib/strategy');