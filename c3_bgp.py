from __future__ import absolute_import
import os

#info on switch
SWITCH_CONTROLLER_INFO = {
    'controller_ip' : "50.0.0.3",
    'controller_mac' : "02:42:ac:1f:00:03",
    'router_ip1' : "33.0.0.2",
    'router_mac1' : "02:42:ac:1a:00:02",
    'router_ip2' : "32.0.0.2",
    'router_mac2' : "02:42:ac:1b:00:02",
    'subnet' : "35.0.0.0/8"
}
#key: is IP controller (of peering), value: is mac of the interface of OF-switch on peering Lan
INFO_ON_OTHER_AS = {
    '50.0.0.1': '02:42:ac:12:00:04',
    '50.0.0.2': '02:42:ac:12:00:02',
    '50.0.0.3': '02:42:ac:12:00:03',	
    '50.0.0.4': '02:42:ac:12:00:05',
    'AS10': '02:42:ac:12:00:04',
    'AS20': '02:42:ac:12:00:02',
    'AS30': '02:42:ac:12:00:03',
    'AS40': '02:42:ac:12:00:05'
}

# =============================================================================
# BGP configuration.
# =============================================================================
BGP = {
    # AS number for this BGP instance.
    'local_as': 30,

    # BGP Router ID.
    'router_id': '50.0.0.3',

    # List of BGP neighbors.
    # The parameters for each neighbor are the same as the arguments of
    # BGPSpeaker.neighbor_add() method.
    'neighbors': [
        {
            'address': '50.0.0.1',
            'remote_as': 10
        },
        {
            'address': '50.0.0.2',
            'remote_as': 20
        },
        {
            'address': '50.0.0.4',
            'remote_as': 40
        }
    ],
    'routes': [
	{
	    'prefix': '80.0.0.0/16'
	}
    ]
}

# =============================================================================
# Logging configuration.
# =============================================================================
LOGGING = {

    # We use python logging package for logging.
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s ' +
                      '[%(process)d %(thread)d] %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(asctime)s %(module)s %(lineno)s ' +
                      '%(message)s'
        },
        'stats': {
            'format': '%(message)s'
        },
    },

    'handlers': {
        # Outputs log to console.
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'console_stats': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'stats'
        },
        # Rotates log file when its size reaches 10MB.
        'log_file': {
            'level': 'ERROR',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join('.', 'bgpspeaker.log'),
            'maxBytes': '10000000',
            'formatter': 'verbose'
        },
        'stats_file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join('.', 'statistics_bgps.log'),
            'maxBytes': '10000000',
            'formatter': 'stats'
        },
    },

    # Fine-grained control of logging per instance.
    'loggers': {
        'bgpspeaker': {
            'handlers': ['console', 'log_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'stats': {
            'handlers': ['stats_file', 'console_stats'],
            'level': 'INFO',
            'propagate': False,
            'formatter': 'stats',
        },
    },

    # Root loggers.
    'root': {
        'handlers': ['console', 'log_file'],
        'level': 'DEBUG',
        'propagate': True,
    },
}
