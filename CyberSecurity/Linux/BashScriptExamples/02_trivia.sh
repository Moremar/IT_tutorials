#!/usr/bin/env bash


#
# Decode the HTML-encoded strings received from the Open Trivial Database API
#
function decode {
  local decoded
  decoded="$1"
  decoded=${decoded//'&quot;'/'"'}      # replace all encoded double quotes
  decoded=${decoded//'&#039;'/$'\''}    # replace all encoded single quotes
  echo "$decoded"
}


#
# Get a trivia question from the Open Trivia database API
# Return the raw JSON result containing the question, the correct answer and wrong answers
#
function get_json_trivia {
  local trivia
  if ! trivia=$(curl -s --fail "https://opentdb.com/api.php?amount=1") ; then
    echo "Issue with the Open Trivia Database API, cannot start the game."
    exit 1
  fi
  echo "$trivia"
}


#
# Get a trivia from the API, display it, ask the user to reply and
# tell if the answer was correct or not
#
function next_trivia {

  # declare all local variable before assignment, so we do not lose the command exit code
  local trivia
  local question
  local correct_answer
  local incorrect_answers_str
  local incorrect_answers_count
  local correct_idx

  trivia=$(get_json_trivia)

  question=$(echo "$trivia" | jq -r ".results[0].question")
  question=$(decode "$question")

  correct_answer=$(echo "$trivia" | jq -r ".results[0].correct_answer")
  correct_answer=$(decode "$correct_answer")

  # get incorrect answers as a multi-line string (1 line per incorrect answer)
  incorrect_answers_str=$(echo "$trivia" | jq -r ".results[0].incorrect_answers[]")
  incorrect_answers_count=$(echo "$trivia" | jq -r ".results[0].incorrect_answers | length")

  # build an incorrect_answers array variable
  local i=0
  while IFS= read -r line ; do
    incorrect_answers[$i]="$line"
    (( i = i + 1 ))
  done <<< "$incorrect_answers_str"

  # choose a random position to insert the correct answer
  correct_idx=$RANDOM
  (( correct_idx = correct_idx % (incorrect_answers_count + 1) ))

  # build the answers array by inserting the correct answer in the incorrect answers
  local offset=0
  for i in $(seq 0 "${incorrect_answers_count}") ; do
    if (( i == correct_idx )) ; then
      answers[$i]="${correct_answer}"
      offset=1
    else
      (( idx_in_incorrect = i - offset ))
      answers[$i]="${incorrect_answers[$idx_in_incorrect]}"
    fi
  done

  # display the question and the answers
  echo -e "\nQUESTION: $question \n"
  for i in $(seq 0 "${incorrect_answers_count}") ; do
    echo "   $i) ${answers[$i]}"
  done

  # prompt for an answer and respond to the user (no proper input validation)
  echo -e ""
  read -r -p "Answer? " user_answer
  if (( user_answer == correct_idx )) ; then
    echo -e "\nCorrect !\n"
  else
    echo -e "\nWrong ! The answer was :  $correct_idx) ${answers[$correct_idx]}\n"
  fi
}


#
# Main function of the program
#
function main {

  keep_playing=0
  while (( keep_playing == 0 )) ; do
  
    # ask a question, suggest answers and gives the correct answer
    next_trivia
  
    # let the user stop if he wants
    read -r -p "Continue playing ? [Y/n] " confirm
    if [[ $confirm == 'n' || $confirm == 'N' ]] ; then
      keep_playing=1
    fi
  
  done
}


# call the main function and forward the arguments received by the script
main "$@"
