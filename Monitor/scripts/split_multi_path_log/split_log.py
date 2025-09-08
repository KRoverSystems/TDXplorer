import os
import re

dir = "path"

def clear_directory(directory):
    """Clear all contents in the directory if it exists."""
    if os.path.exists(directory):
        # List all files and directories in the directory
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            try:
                # Remove the file or directory
                if os.path.isdir(file_path):
                    os.rmdir(file_path)  # Remove the directory (only if empty)
                else:
                    os.remove(file_path)  # Remove the file
            except Exception as e:
                print(f"Error removing {file_path}: {e}")

def split_file(input_file):
    # Clear the directory contents before starting the processing, only if directory exists
    if os.path.exists(dir):
        clear_directory(dir)

    # Ensure the paths directory exists (it will be created if it doesn't exist)
    if not os.path.exists(dir):
        os.makedirs(dir)

    # Define the pattern to identify a new path section
    pattern = r'starting a new path: (\d+)'

    # Prepare to collect unreachable constraints
    unreachable_constraints = []

    # Open the input file and process it line by line
    with open(input_file, 'r') as file:
        current_path_number = None
        current_content = []
        initial_capture_done = False
        
        for line in file:
            # Check if the line matches the starting pattern for a new path
            match = re.match(pattern, line)
            
            if current_path_number is None and not initial_capture_done:
                # Capture lines before the first 'starting a new path' match
                current_content.append(line)
            
            if match and not initial_capture_done:
                # Once the first path is encountered, write the initial capture
                with open(f'{dir}/0-trace-until-path-0.log', 'w') as output_file:
                    output_file.writelines(current_content)
                initial_capture_done = True  # Mark that we have already captured up to the first path
                
                # Clear the initial content since we have captured it
                current_content = []
            
            if match:
                # If we're already collecting content for a previous path, write it to a file
                if current_path_number is not None:
                    # Determine the appropriate suffix for the last path
                    if 'SEAMRET: FAIL' in ''.join(current_content):
                        suffix = '_SEAMRET_FAIL'
                    elif 'SEAMRET: SUCCESS' in ''.join(current_content):
                        suffix = '_SEAMRET_SUCCESS'
                    elif 'endCurrentPathReason: 3' in ''.join(current_content):
                        suffix = '_loop' 
                    elif 'impossible path' in ''.join(current_content):
                        suffix = '_imposbl'                     
                    # elif 'endCurrentPathReason: 4' in ''.join(current_content):
                    elif 'UD2 instruction detected' in ''.join(current_content):
                        suffix = '_ud2' 
                    elif 'AT FUNCTION RET: NEW MAPPING' in ''.join(current_content):
                        suffix = '_FUN_RET_NEW_M' 
                    elif 'AT FUNCTION RET: EXISTING MAPPING' in ''.join(current_content):
                        suffix = '_FUN_RET_EXI_M' 
                    else:
                        suffix = '_NONE'
                    
                    # Process and extract last constraint for unreachable paths
                    last_constraint = extract_last_constraint(current_content)
                    if last_constraint:
                        # print(f"Found unreachable path constraint: {last_constraint}")
                        # Add the constraint to the list for later writing
                        unreachable_constraints.append(f'"path-{current_path_number.zfill(3)}", "{last_constraint}",')
                    # else:
                    #     print(f"No last constraint found for path {current_path_number.zfill(3)}")

                    # Create the file name
                    path_filename = f'{dir}/path_{current_path_number}{suffix}.log'
                    
                    # Write the content of the current path to a file
                    with open(path_filename, 'w') as output_file:
                        output_file.writelines(current_content)
                
                # Start a new path collection
                current_path_number = match.group(1)
                current_content = [line]
            else:
                # Otherwise, keep adding lines to the current path content
                if current_path_number is not None:
                    current_content.append(line)

        # Write the last path after the loop finishes
        if current_path_number is not None:
            # Determine the appropriate suffix for the last path
            if 'FUNCTION_RET' in ''.join(current_content):
                suffix = '_Func_END'
            elif 'PT_MAP' in ''.join(current_content):
                suffix = 'PT_MAP'
            elif 'endCurrentPathReason: 0' in ''.join(current_content):
                suffix = 'New_PTE' 
            elif 'endCurrentPathReason: 3' in ''.join(current_content):
                suffix = '_loop' 
            elif 'endCurrentPathReason: 2' in ''.join(current_content):
                suffix = '_drop' 
            elif 'endCurrentPathReason: 4' in ''.join(current_content):
                suffix = '_ud2' 
            else:
                suffix = '_NONE'

            # Process and extract last constraint for unreachable paths
            last_constraint = extract_last_constraint(current_content)
            if last_constraint:
                # print(f"Found unreachable path constraint: {last_constraint}")
                # Add the constraint to the list for later writing
                unreachable_constraints.append(f'"path-{current_path_number.zfill(3)}", "{last_constraint}"')
            # else:
                # print(f"No last constraint found for path {current_path_number.zfill(3)}")
            
            # Create the file name
            path_filename = f'{dir}/path_{current_path_number}{suffix}.log'
            
            # Write the content to the file
            with open(path_filename, 'w') as output_file:
                output_file.writelines(current_content)

    # After processing all paths, write all unreachable path constraints to the log using writelines()
    if unreachable_constraints:
        unreachable_constraints_filename = f'{dir}/0-Unreachable-path-constraints.log'
        with open(unreachable_constraints_filename, 'w') as u_file:
            u_file.writelines([line + "\n" for line in unreachable_constraints])  # Use writelines()
    else:
        print("unreachable_constraints is empty")

    print("File split into paths and unreachable constraints written successfully.")

def extract_last_constraint(content):
    """Extract the last constraint starting with 'Last_constraint:' and remove all spaces and tabs."""
    for line in reversed(content):
        if line.startswith("Last_constraint:"):
            # Take the part of the line after "Last_constraint:", remove spaces and tabs
            return line[len("Last_constraint:"):].strip().replace(" ", "").replace("\t", "")
    return None  # Return None if no valid constraint is found

# Example usage
# split_file('sept-add-multi-log')  # Replace 'input.txt' with the name of your input file
split_file('input.txt')  # Replace 'input.txt' with the name of your input file
