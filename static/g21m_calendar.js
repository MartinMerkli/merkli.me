let calendar_month_names = ['   Januar', '  Februar', '     März', '    April', '      Mai', '     Juni', '     Juli', '   August', 'September', ' Oktober', ' November', ' Dezember']
let calendar_type_colors = ['red', 'orange', 'magenta', 'lime', 'cyan', 'gray']
let calendar_month_lengths = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
let calendar_selected_year = calendar_current_date[0]
let calendar_selected_month = calendar_current_date[1]
let calendar_year_length = 365
let calendar_leap_years = [2024, 2028]
let calendar_last_2021 = 4
function calendar_next_month(){
    if(calendar_selected_month === 12){
        calendar_selected_month = 1
        calendar_selected_year++
    }else{
        calendar_selected_month++
    }
    calendar_reload()
}
function calendar_previous_month(){
    if(calendar_selected_month === 1){
        calendar_selected_month = 12
        calendar_selected_year--
    }else{
        calendar_selected_month--
    }
    calendar_reload()
}
function calendar_to_days(year, month, day){
    let counter = 1
    let year_difference = year - 2022
    for(let i = 0; i < year_difference; i++){
        counter += calendar_year_length
        if(calendar_leap_years.includes(year_difference + 2022)){
            counter++
        }
    }
    for(let i = 0; i < month - 1; i++){
        counter += calendar_month_lengths[i]
        if(calendar_leap_years.includes(year_difference + 2022) && month === 2){
            counter++
        }
    }
    counter += day - 1
    return counter
}
function calendar_date_to_string(year, month, day){
    let string = year.toString() + '-'
    let month_string = month.toString()
    if(month_string.length === 2){
        string += month_string + '-'
    }else{
        string += '0' + month_string + '-'
    }
    let day_string = day.toString()
    if(day_string.length === 2){
        string += day_string
    }else{
        string += '0' + day_string
    }
    return string
}
function calendar_time_formater(time, mode){
    let parts = time.split('_')
    switch (mode) {
        case 0:
            return time
        case 1:
            return parts[0]
        case 2:
            return parts[1]
        case 3:
            return parts[1].replace('-', ':')
        case 4:
            return parts[0] + ', ' + parts[1].replace('-', ':')
        default:
            return ''
    }
}
function calendar_reload(){
    if(calendar_selected_year === 2021){
        alert('der Kalender funktioniert erst ab dem Jahr 2022')
        calendar_selected_year = 2022
        calendar_selected_month = 1
    }else if(calendar_selected_year === 2027){
        alert('der Kalender funktioniert nur bis zu dem Jahr 2026')
        calendar_selected_year = 2026
        calendar_selected_month = 12
    }
    document.getElementById('calendar_month_name').innerText = calendar_month_names[calendar_selected_month - 1]
    document.getElementById('calendar_year_number').innerText = calendar_selected_year.toString()
    let first_day = calendar_to_days(calendar_selected_year, calendar_selected_month, 1)
    let first_day_grid = (calendar_last_2021 + first_day) % 7
    let month_length = calendar_month_lengths[calendar_selected_month - 1]
    if(calendar_leap_years.includes(calendar_selected_year) && calendar_selected_month === 2){
        month_length++
    }
    for(let i = 0; i < 42; i++){
        document.getElementById('calendar_day-date-' + i.toString()).innerText = ''
        document.getElementById('calendar_day-' + i.toString()).style.backgroundColor = window.getComputedStyle(document.getElementById('calendar_not-selected')).color
        document.getElementById('calendar_day-list-' + i.toString()).innerHTML = ''
    }
    for(let i = 0; i < month_length; i++){
        let date = calendar_date_to_string(calendar_selected_year, calendar_selected_month, i + 1)
        document.getElementById('calendar_day-date-' + (i + first_day_grid).toString()).innerText = date
        document.getElementById('calendar_day-' + (i + first_day_grid).toString()).style.backgroundColor = window.getComputedStyle(document.getElementById('calendar_selected')).color
        let events = ''
        for(let j = 0; j < calendar_data.length; j++){
            if(date === calendar_data[j]['start_date'].split('_')[0]){
                let event_name = ''
                if(calendar_data[j]['start_date'] === calendar_data[j]['end_date']){
                    event_name += `[${calendar_time_formater(calendar_data[j]['start_date'], 3)}]`
                }else if(calendar_data[j]['start_date'].split('_')[0] === calendar_data[j]['end_date'].split('_')[0]){
                    event_name += `[${calendar_time_formater(calendar_data[j]['start_date'], 3)} bis ${calendar_time_formater(calendar_data[j]['end_date'], 3)}]`
                }else{
                    event_name += `[${calendar_time_formater(calendar_data[j]['start_date'], 4)} bis ${calendar_time_formater(calendar_data[j]['end_date'], 4)}]`
                }
                event_name += ' <b>' + calendar_data[j]['name'] + '</b>'
                events += `<li><div class="calendar_event" style="color: ${calendar_type_colors[calendar_data[j]['type']]}"><p>${event_name}</p></div></li>`
            }
        }
        document.getElementById('calendar_day-list-' + (i + first_day_grid).toString()).innerHTML = events
        if(date === calendar_date_to_string(calendar_current_date[0], calendar_current_date[1], calendar_current_date[2])){
            document.getElementById('calendar_day-' + (i + first_day_grid).toString()).style.backgroundColor = window.getComputedStyle(document.getElementById('calendar_current-date')).color
        }
    }
}
