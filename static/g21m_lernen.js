
// element ID selector
function learn_$(element_id){
    return document.getElementById(element_id);
}

// current exercise
let learn_cur_exercise = '';

// GUI
function learn_switch_window(new_front){
    let all_windows = ['learn_div_exercise', 'learn_div_result', 'learn_div_loading', 'learn_div_other_error'];
    for(let i in all_windows){
        learn_$(all_windows[i]).style.display = 'none';
    }
    learn_$(new_front).style.display = 'block';
}

// show no internet error message
function learn_connection_error(status){
    console.log(status)
    learn_$('learn_div_connection_error').style.display = 'block';
}

// send stats
function learn_send_answer(ex_id, answer, is_correct, ids){
    let string_ids = ids.join('-');
    let url = '/nachhilfe/2lernen2/' + string_ids + '/' + ex_id + '/';
    let parts = ex_id.split('_');
    let stats_id = learn_string_sets() + '_' + parts[1];
    if(is_correct){
        url = url + '1';
        if(stats_id in learn_stats){
            if('correct' in learn_stats[stats_id]){
                learn_stats[stats_id]['correct']++;
            } else{
                learn_stats[stats_id]['correct'] = 1;
            }
        } else{
            learn_stats[stats_id] = {'correct': 1, 'wrong': 0};
        }
    } else{
        url = url + '0';
        if(stats_id in learn_stats){
            if('wrong' in learn_stats[stats_id]){
                learn_stats[stats_id]['wrong']++;
            } else{
                learn_stats[stats_id]['wrong'] = 1;
            }
        } else{
            learn_stats[stats_id] = {'wrong': 1, 'correct': 0};
        }
    }
    if(learn_is_signed_in){
        learn_jq.ajax({url : url, contentType : 'text/plain', dataType : 'text', timeout : 2000, method : 'POST', data : answer, error : learn_connection_error});
    }
}

// get a combined name of all sets
function learn_get_sets_name(){
    let result = '';
    for(const i in learn_sets){
        result += learn_sets[i]['name'] + ', ';
    }
    return result.slice(0, -2);
}

// list all set-ids
function learn_list_ids(){
    let r = [];
    for(const i in learn_sets){
        r.push(i)
    }
    return r;
}

// how do I describe this function?
function learn_string_sets(){
    let r = '';
    for(const i in learn_sets){
        r += i + '-';
    }
    if(r.length > 0){
        if(r.slice(-1) === '-'){
            r = r.slice(0, -1);
        }
    }
    return r;
}

// calculate stats
function learn_calculate_stats(){
    let r = {'wrong': 0, 'total': 0, 'correct': 0, 'answered': 0};
    for(const i in learn_stats){
        if(i.split('_')[0] === learn_string_sets()){
            r['wrong'] += learn_stats[i]['wrong'];
            r['correct'] += learn_stats[i]['correct'];
            r['answered'] += 1;
        }
    }
    let total = 0;
    for(const i in learn_sets){
        total += Object.keys(learn_sets[i]['exercises']).length;
    }
    r['total'] = total;
    return r;
}

// show next exercise
function learn_next_exercise(){
    document.getElementById('learn_textarea_input').value = ''
    let chances = {};
    for(const i in learn_sets){
        for(const j in learn_sets[i]['exercises']){
            let ex_id = i + '_' + j;
            if(learn_stats.hasOwnProperty(ex_id)){
                chances[ex_id] = Math.max(learn_stats[ex_id]['wrong'] * 3 - learn_stats[ex_id]['correct'] * 2 + 1, 0.05) * learn_sets[i]['exercises'][j]['frequency'];
            } else{
                chances[ex_id] = learn_sets[i]['exercises'][j]['frequency'] * 4 + 1;
            }
        }
    }
    let total = 0.0;
    for(const i in chances){
        total = total + chances[i];
    }
    if(total === 0.0){
        learn_switch_window('learn_div_other_error');
    }
    let choice = total * Math.random();
    let next_exercise = '';
    let total2 = 0.0;
    for(const i in chances){
        if((next_exercise === '') && ((chances[i] + total2) >= choice)){
            next_exercise = i;
        }
        total2 += chances[i];
    }

    learn_cur_exercise = next_exercise

    let parts = next_exercise.split('_');
    learn_$('learn_exercise_question').innerHTML = learn_sets[parts[0]]['exercises'][parts[1]]['question'];

    let ex_links = learn_sets[parts[0]]['exercises'][parts[1]]['links'];
    let display_links = '';
    for(let i = 0; i < ex_links.length; i++){
        display_links += '<li><a href="' + ex_links[i] + '"></a></li>';
    }
    learn_$('learn_exercise_links').innerHTML = display_links;

    let ex_images = learn_sets[parts[0]]['exercises'][parts[1]]['images'];
    let display_images = '';
    for(let i = 0; i < ex_images.length; i++){
        display_images += '<li><img alt="" src="' + ex_images[i] + '"></li>';
    }
    learn_$('learn_exercise_images').innerHTML = display_images;

    learn_$('learn_exercise_name').innerHTML = learn_get_sets_name();

    let s = learn_calculate_stats();
    let progress = '--%';
    if(s['total'] !== 0){
        progress = Math.round((s['correct'] + s['wrong']) / s['total'] * 100).toString() + '%';
    }
    let grade = '~ -';
    if(s['correct'] + s['wrong'] !== 0){
        grade = '~' + (Math.round((s['correct'] / (s['correct'] + s['wrong']) * 5 + 1) * 10) / 10).toString();
    }
    total = s['answered'].toString() + ' von ' + s['total'].toString();
    learn_$('learn_exercise_stats').innerHTML = 'Fortschritt: ' + progress + ' | Note: ' + grade + ' | Total: ' + total;
    learn_switch_window('learn_div_exercise');
    learn_$('learn_textarea_input').focus();
}

// autocorrect
function learn_is_correct(input){
    let parts = learn_cur_exercise.split('_');
    return !!learn_sets[parts[0]]['exercises'][parts[1]]['answers'].includes(input.replaceAll('\n', ''));

}

// if button is pressed
function learn_check_input(){
    learn_$('learn_div_connection_error').style.display = 'none';
    let input = learn_$('learn_textarea_input').value;
    let parts = learn_cur_exercise.split('_');
    if(learn_is_correct(input)){
        learn_send_answer(learn_cur_exercise, input, true, learn_list_ids());
        learn_next_exercise();
        return null;
    }
    learn_$('learn_result_question').innerHTML = learn_sets[parts[0]]['exercises'][parts[1]]['question'];

    let ex_links = learn_sets[parts[0]]['exercises'][parts[1]]['links'];
    let display_links = '';
    for(let i = 0; i < ex_links.length; i++){
        display_links += '<li><a href="' + ex_links[i] + '"></a></li>';
    }
    learn_$('learn_result_links').innerHTML = display_links;

    let ex_images = learn_sets[parts[0]]['exercises'][parts[1]]['images'];
    let display_images = '';
    for(let i = 0; i < ex_images.length; i++){
        display_images += '<li><img alt="" src="' + ex_images[i] + '"></li>';
    }
    learn_$('learn_result_images').innerHTML = display_images;

    learn_$('learn_result_name').innerHTML = learn_get_sets_name();

    let s = learn_calculate_stats();
    let progress = '--%';
    if(s['total'] !== 0){
        progress = Math.round((s['correct'] + s['wrong']) / s['total'] * 100).toString() + '%';
    }
    let grade = '~ -';
    if(s['correct'] + s['wrong'] !== 0){
        grade = '~' + (Math.round((s['correct'] / (s['correct'] + s['wrong']) * 5 + 1) * 10) / 10).toString();
    }
    let total = s['answered'].toString() + ' von ' + s['total'].toString();
    learn_$('learn_result_stats').innerHTML = 'Fortschritt: ' + progress + ' | Note: ' + grade + ' | Total: ' + total;

    learn_$('learn_result_ans').innerHTML = learn_sets[parts[0]]['exercises'][parts[1]]['answer'];

    let ex_ans_links = learn_sets[parts[0]]['exercises'][parts[1]]['answer_links'];
    let display_ans_links = '';
    for(let i = 0; i < ex_ans_links.length; i++){
        display_ans_links += '<li><a href="' + ex_ans_links[i] + '"></a></li>';
    }
    learn_$('learn_result_ans_links').innerHTML = display_ans_links;

    let ex_ans_images = learn_sets[parts[0]]['exercises'][parts[1]]['answer_images'];
    let display_ans_images = '';
    for(let i = 0; i < ex_ans_images.length; i++){
        display_ans_images += '<li><img alt="" src="' + ex_ans_images[i] + '"></li>';
    }
    learn_$('learn_result_ans_images').innerHTML = display_ans_images;

    learn_$('learn_result_input').innerHTML = input;

    learn_switch_window('learn_div_result');
    learn_$('learn_correct_button').focus();
}

// correct_button
function learn_submit_correct(){
    let input = learn_$('learn_textarea_input').value;
    learn_send_answer(learn_cur_exercise, input, true, learn_list_ids());
    learn_next_exercise();
}

// wrong_button
function learn_submit_wrong(){
    let input = learn_$('learn_textarea_input').value;
    learn_send_answer(learn_cur_exercise, input, false, learn_list_ids());
    learn_next_exercise();
}

function learn_init(){
    function submitOnEnter(event){
        if(event.which === 13 && !event.shiftKey){
            learn_check_input();
            event.preventDefault();
        }
    }
    let area = document.getElementById("learn_textarea_input");
    area.addEventListener("keypress", submitOnEnter);

    learn_next_exercise();
}
