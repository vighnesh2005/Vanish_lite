all:
	g++ engine/main.cpp \
	engine/session.cpp \
	engine/policy_enforcer.cpp \
	engine/session_manager.cpp \
	engine/utils.cpp \
	-o vanish
	g++ -std=c++17 engine/user_netguard.cpp -o vanish_user_netguard
	g++ -std=c++17 -shared -fPIC engine/netguard_preload.cpp -ldl -o libvanish_netguard.so

admin-panel:
	python3 admin_panel/server.py

clean:
	rm -f vanish
	rm -f vanish_user_netguard
	rm -f libvanish_netguard.so
