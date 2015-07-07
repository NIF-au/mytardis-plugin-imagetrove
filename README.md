# mytardis-plugin-imagetrove

Plugin for MyTARDIS for the imagetrove-uploader.

## Compatability

This plugin is aimed at the bleeding edge ```develop``` branch of
MyTARDIS, as at June 2015.

Use the v1.1 tag of imagetrove-uploader or later: https://github.com/NIF-au/imagetrove-uploader/releases/tag/v1.1

## Installation

Clone this repository into your mytardis apps directory:

    cd /opt/mytardis/develop/tardis/apps
    git clone https://github.com/NIF-au/mytardis-plugin-imagetrove.git imagetrove

If configuring manually, run

    cd /opt/mytardis/develop/tardis/apps/imagetrove
    pip install -r requirements.txt

Otherwise, install the required packages using your Dockerfile.

Add the plugin (app) to the ```INSTALLED_APPS``` setting in ```tardis/settings.py```:

    INSTALLED_APPS += ('tardis.apps.imagetrove',)

## Test

View ```http://<your-mytardis-host>/api/v1/?format=json``` and you
should see a number of URLs with an ```imagetrove_``` prefix.
