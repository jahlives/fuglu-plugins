# URIExtract
A set of plugins to perform:
- uri extraction of the message content
- blacklist lookups of found uris
- adding tags for found listings so following plugins can catch up on them

This plugin requires the domainmagic libary found at https://github.com/gryphius/domainmagic

This plugin consists of two parts. First the base plugin uriextract.py and an additional plugin for adding a header in add_header_uriextract.py. To use both plugins the first one needs the setting

pluginfollows = 1

which tells the main plugin that a following plugin performs the final decission and therefore action DUNNO should be returned upon match on blacklist.
To use both plugins set the follwing in /etc/fuglu/fuglu.conf

plugins=plugins.uriextract.URIExtract,fuglu.plugins.uriextract.DomainAction,fuglu.plugins.add_uriextract_header.URIExtractAddHeader

to fully enable the two plugins. To enable adding headers set the config section for the plugin

[URIExtractAddHeader]
add_header_links=1
add_header_count=1

the first option enables a header that lists the uris of all blacklisted hosts and the 2nd adds a header with a count of how many uris in the message matches the blacklist.
