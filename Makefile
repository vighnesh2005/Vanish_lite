all:
	g++ engine/main.cpp \
	engine/session.cpp \
	engine/policy_enforcer.cpp \
	engine/session_manager.cpp \
	engine/utils.cpp \
	engine/exam_controller.cpp \
	engine/monitor.cpp \
	-o vanish

clean:
	rm -f vanish