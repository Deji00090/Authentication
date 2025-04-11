﻿using System.ComponentModel.DataAnnotations;

namespace Authentication.Model
{
       public class AddRoleModel
        {
            [Required]
            public string Email { get; set; }
            [Required]
            public string Password { get; set; }
            [Required]
            public string Role { get; set; }
        }
    
}
