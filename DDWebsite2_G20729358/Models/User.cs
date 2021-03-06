//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace DDWebsite2_G20729358.Models
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public partial class User
    {
        public int Id { get; set; }
        [StringLength(25, MinimumLength = 3)]
        [Required]
        [Index(IsUnique = true)]
        public string Username { get; set; }
        [StringLength(25, MinimumLength = 0)]

        public string Firstname { get; set; }
        [StringLength(25, MinimumLength = 0)]

        public string Lastname { get; set; }
        [Required]
        [DataType(DataType.EmailAddress)]
        [RegularExpression(@"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")]
        public string Email { get; set; }
        [StringLength(512, MinimumLength = 3)]
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [StringLength(512, MinimumLength = 3)]
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation do not match.")]
        public string ConfirmPassword { get; set; }
        [StringLength(30, MinimumLength =0)]
        public string UserRole { get; set; }
    }
}
