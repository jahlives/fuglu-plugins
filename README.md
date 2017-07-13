# fuglu-plugins
These plugins are mostly (except for one) based on the stock plugins https://github.com/gryphius/fuglu/tree/master/fuglu/src/fuglu/plugins. The one exception from the above is from extra-plugins https://github.com/gryphius/fuglu-extra-plugins 
Most changes are related to the ability to append headers to messages processed. This is mostly useful for plugins with DUNNO action, so headers are added for following plugins to catch up.

## TODO
- change stock plugins to add tags instead of directly adding headers. Currently only urieextract plugin works like that. Helps to minimize changes to the stock plugins codes
- create a "generic" addheader plugin to catch the set tags from other plugins
- code optimization and cleanup (never ending story ;-) )
