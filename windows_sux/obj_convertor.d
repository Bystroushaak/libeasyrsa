import std.stdio;
import std.file;
import std.string;
import std.process;
import std.array;

void main(){
	foreach(string fn; dirEntries(".", SpanMode.depth)){
		if (!fn.endsWith(".o"))
			continue;
		
		fn = fn.split("\\")[$-1];
		
		writeln(fn.replace(".o", ".obj") ~ ":");
		system("objconv -fomf " ~ fn ~ " " ~ fn.replace(".o", ".obj"));
		
	}
}
