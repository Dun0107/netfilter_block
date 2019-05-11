TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lnetfilter_queue -lnfnetlink -lpcap

SOURCES += nfqnl_test.c



