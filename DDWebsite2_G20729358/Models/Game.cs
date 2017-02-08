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
    
    public partial class Game
    {
        public int Id { get; set; }
        [StringLength(50, MinimumLength = 1)]
        [Required]
        public string Title { get; set; }
        [StringLength(100, MinimumLength = 0)]
        public string Description { get; set; }
        [StringLength(50, MinimumLength = 0)]
        public string Developer { get; set; }
        [StringLength(50, MinimumLength = 0)]
        public string Publisher { get; set; }
        [DisplayFormat(DataFormatString = "{0:yyyy-MM-dd}", ApplyFormatInEditMode = true)]
        [DataType(DataType.Date)]
        [Display(Name = "Release Date")]
        public Nullable<System.DateTime> Release { get; set; }
        [RegularExpression(@"^\d+.\d{0,2}$", ErrorMessage = "Price can't have more than 2 decimal places")]
        [DataType(DataType.Currency)]
        [Range(0.00, 10000)]
        public Nullable<decimal> Price { get; set; }
    }
}
