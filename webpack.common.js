const path = require('path');

module.exports = {
	entry: {
		'main': './src/main.js'
	},
	output: {
		filename: '[name].js',
		path: path.resolve(__dirname, 'dist')
	},
	externals: {
		'js-sandbox': 'Sandbox',
		mustache: 'Mustache'
	}
};