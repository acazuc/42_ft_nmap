/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   colors.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ele-goug <ele-goug@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/11/02 21:26:36 by ele-goug          #+#    #+#             */
/*   Updated: 2014/11/02 21:26:37 by ele-goug         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef COLORS_H
# define COLORS_H

# define DEFAULT "\x1B[0m"
# define GREY "\x1B[38;5;252m"
# define DARK "\x1B[38;5;246m"
# define RED "\x1B[38;5;203m"
# define GREEN "\x1B[38;5;119m"
# define YELLOW "\x1B[38;5;227m"
# define BLUE "\x1B[38;5;069m"
# define MAGENTA "\x1B[38;5;207m"
# define CYAN "\x1B[38;5;087m"
# define WHITE "\x1B[38;5;231m"

# define PINK "\033[38;5;219m"
# define PEACHY "\033[38;5;215m"
# define SKY "\033[38;5;117m"
# define INDIGO "\033[38;5;099m"
# define PURPLE "\033[38;5;141m"
# define FOAM "\033[38;5;155m"
# define SPRING "\033[38;5;112m"

# define CAS( n ) "\033[38;5;" #n "m"

#endif
