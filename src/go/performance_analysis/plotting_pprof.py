import subprocess
import pandas as pd
import sys

# First parameter is input path, second is output path
in_name = sys.argv[1]
out_name = sys.argv[2]

pprof_path = "../examples/priority_drop_video/build/prof/"
pprof_name = in_name

need_escape = ["%", "_", "&", "#", "$", "{", "}", "~", "^"]
remove_from_causes = ["github.com/danielpfeifer02", "github.com"] # "github.com/danielpfeifer02" has to be before "github.com"

def table_for_command(input, name="table"):

    process = subprocess.Popen(
        ['go', 'tool', 'pprof', pprof_path + pprof_name],
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE,
        text=True
    )

    # Send the command to the `pprof` interactive session
    output, error = process.communicate(input=input)
    output = output.split('\n')

    identifiers = output[2].split() + ["cause"]
    for i in range(len(identifiers)):
        for escape in need_escape:
            if escape in identifiers[i]:
                identifiers[i] = identifiers[i].replace(escape, "\\"+escape)
    print(identifiers)

    df = pd.DataFrame(columns=identifiers)

    for line in output[3:-1]:
        line = line.replace(" (inline)", "")
        elements = line.split()
        # print(elements)

        # If an element contains a "%" we need to escape it for latex
        for i in range(len(elements)):
            for escape in need_escape:
                if escape in elements[i]:
                    elements[i] = elements[i].replace(escape, "\\"+escape)
            for cause in remove_from_causes:
                if cause in elements[i]:
                    elements[i] = elements[i].replace(cause, "...")

        assert len(elements) == len(identifiers), f"{elements} vs. {identifiers}"
        df.loc[len(df)] = {identifiers[i]: elements[i] for i in range(len(elements))}

    print(df)

    caption = f"Table for {'cumulative ' if 'cum' in name else ''}CPU usage of relay Go processes"

    # Export the DataFrame to a LaTeX table
    latex_table = df.to_latex(index=False, caption=caption, label='tab:example')

    # Save the LaTeX table to a .tex file
    with open("./output/tables/"+name+".tex", 'w') as f:
        f.write(latex_table)


table_for_command("top 5\n", out_name+"_table_top")
table_for_command("top -cum 5\n", out_name+"_table_top_cum")