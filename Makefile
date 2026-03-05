all:
	g++ engine/main.cpp engine/session.cpp engine/policy_enforcer.cpp -o vanish

clean:
	rm -f vanish