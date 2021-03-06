package main

denylist = ["python", "node", "ruby", "openjdk"]

deny[msg] {
	input[i].Cmd == "from"
	val := input[i].Value
	contains(val[i], denylist[_])

	msg = sprintf("unallowed image found %s", [val])
}
