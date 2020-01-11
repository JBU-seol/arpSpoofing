TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap -lpthread
SOURCES += \
        arpManage.cpp \
        extraFunc.cpp \
        main.cpp

HEADERS += \
    arpManage.h \
    extraFunc.h
