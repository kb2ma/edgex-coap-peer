EdgeX CoAP Peer
###############

Overview
********
This project provides a Zephyr based CoAP peer example for the EdgeX device-coap-c_ project.

This example will make POST requests to device-coap-c's resource for asynchronously generated data. The example includes sample Kconfig files for both DTLS PSK and nosec security.

The example sends a POST to:

.. code-block:: console

    coap(s)://172.17.0.1/a1r/d1/int

In other words the protocol portion either is ``coaps`` for DTLS or ``coap`` for nosec. The example assumes the device is named ``d1`` in EdgeX.

Building and Running
********************

This example includes a ``prj.conf`` to initialize the build. The example also includes two complete Kconfig setups ``dtls.config`` and ``nosec.config`` which can be copied to ``./build/zephyr/.config`` for a `native_posix` build.

For a DTLS PSK build, the client identity and key are defined in ``src/dummy_psk.h``. The key must match the key used in the device-coap-c service.

A run of the app sends three POST requests, separated by three seconds. The output should look like:

.. code-block:: console

    UART_0 connected to pseudotty: /dev/pts/9
    WARNING: Using a test - not safe - entropy source
    *** Booting Zephyr OS build zephyr-v2.3.0-2295-gc2b567f79e63  ***
    
    CoAP client POST
    
    CoAP client POST
    
    CoAP client POST

.. _device-coap-c: https://github.com/kb2ma/device-coap-c
