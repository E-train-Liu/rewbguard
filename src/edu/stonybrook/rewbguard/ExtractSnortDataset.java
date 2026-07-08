package edu.stonybrook.rewbguard;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.ArrayList;

import org.json.JSONArray;
import org.json.JSONObject;

public class ExtractSnortDataset {
	public static void main(String[] args) throws IOException {
		ArrayList<RPattern> rpatterns = DataLoadSave.loadSnortRulesDirPattern(Path.of("data/exp/snort2-register-rules"));
		rpatterns = DataLoadSave.mergeRepeatRPattern(rpatterns);
		JSONArray json = new JSONArray();
		StringBuilder toml = new StringBuilder();
		for (RPattern rpattern : rpatterns) {
			JSONObject jsonObj = new JSONObject();
			jsonObj.put("pattern", rpattern.pattern);
			jsonObj.put("flags", rpattern.flags);
			jsonObj.put("sources", rpattern.sources);
			json.put(jsonObj);

			toml
				.append("[regexes]\n")
				.append("pattern = ").append(DataLoadSave.toTomlString(rpattern.pattern)).append('\n')
				.append("flags = ").append(DataLoadSave.toTomlString(rpattern.flags)).append('\n')
				.append("sources = [\n");
			for (String source : rpattern.sources)
				toml.append("    ").append(DataLoadSave.toTomlString(source)).append(",\n");
			toml.append("]\n\n");
		}
		FileWriter jsonFile = new FileWriter("data/exp/snort2-register-regexes.json");
		jsonFile.write(json.toString(2));
		jsonFile.close();
		FileWriter tomlFile = new FileWriter("data/exp/snort2-register-regexes.toml");
		tomlFile.write(toml.toString());
		tomlFile.close();
	}
}
