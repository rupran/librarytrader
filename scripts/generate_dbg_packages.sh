packages=$(for line in $(cat library_paths); do \
			t=$(readlink -f $line); \
			pkg=$(dpkg -S $t | cut -d: -f1);
			echo $pkg; \
			done \
		| sort -u)
tmpfile="$(mktemp)"

for line in $(echo $packages | tr ' ' '\n'); do
	ver="=$(dpkg -l $line | tr -s ' ' | cut -d' ' -f3 | tail -n1)"
	sym="$line-dbgsym";
	r="$(apt -qqq list $sym)";
	if [ -n "$r" ]; then
		echo "$sym$ver";
	else
		sym="$line-dbg";
		r="$(apt list -qqq $sym)";
		if [ -n "$r" ]; then
			echo "$sym$ver";
		else
			echo "XXX: No package for $line";
		fi;
	fi;
done 2>/dev/null > "$tmpfile"

grep 'XXX' "$tmpfile" > dbg_packages_missing
grep -v 'XXX' "$tmpfile" > dbg_packages_existing
